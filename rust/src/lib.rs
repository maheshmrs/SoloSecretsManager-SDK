//! Read secrets from a SoloSecretsManager server inside CI jobs (SDK-01, SEC-MACH-02).
//!
//! The server only returns ciphertext. The job proves who it is with a GitHub Actions OIDC token, gets the
//! environment key wrapped under `SSM_CI_KEY`, and decrypts in memory with `ssm-core-read` (SDK-02). Nothing is
//! written to disk (SDK-06). Checked against `testvectors/machine-v1.json` (QA-G-03).
//!
//! ```no_run
//! let mut c = solosecretsmanager::Client::from_env()?;
//! let password = c.get("DATABASE_PASSWORD")?;
//! # Ok::<(), solosecretsmanager::Error>(())
//! ```

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ssm_core_read::{Key, ObjectRef, RustCrypto, open, unwrap_key};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub mod cloud;

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ssm: {}", self.0)
    }
}

impl std::error::Error for Error {}

fn err<T>(m: impl Into<String>) -> Result<T, Error> {
    Err(Error(m.into()))
}

fn b64(s: &str) -> Result<Vec<u8>, Error> {
    B64.decode(s.trim().trim_end_matches('='))
        .map_err(|_| Error("malformed base64".into()))
}

fn uuid(s: &str) -> Result<[u8; 16], Error> {
    let h: String = s.chars().filter(|c| *c != '-').collect();
    if h.len() != 32 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return err("bad UUID");
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
    }
    Ok(out)
}

fn ci_key(s: &str) -> Result<Key, Error> {
    let raw = Zeroizing::new(b64(s)?);
    if raw.len() != 48 {
        return err("SSM_CI_KEY is missing or malformed");
    }
    Ok(Key::new(
        raw[..16].try_into().unwrap(),
        raw[16..].try_into().unwrap(),
    ))
}

fn decrypt_failed(_: ssm_core_read::Error) -> Error {
    Error("decryption failed (tampered, swapped or wrong key)".into())
}

/// Opens the environment key with the CI key, then each item (SEC-MACH-05). Any failure fails the whole call.
pub fn decrypt_exchange(
    ci: &str,
    environment_id: &str,
    exchange: &Value,
) -> Result<HashMap<String, String>, Error> {
    let b = &RustCrypto;
    let ci = ci_key(ci)?;
    let str_of = |v: &Value| {
        v.as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error("malformed exchange".into()))
    };
    let env = uuid(environment_id)?;
    let ek = unwrap_key(
        b,
        &ci,
        ObjectRef {
            id: env,
            revision: 0,
        },
        &b64(&str_of(&exchange["wrapped_key"])?)?,
    )
    .map_err(decrypt_failed)?;
    decrypt_items(&ek, exchange)
}

/// What a cloud KMS decrypted: environment ID ‖ key ID ‖ key; it must be this environment's (SEC-MACH-06/08/09).
pub fn cloud_env_key(plain: &[u8], environment_id: &str) -> Result<Key, Error> {
    if plain.len() != 64 || plain[..16] != uuid(environment_id)? {
        return err("KMS returned a key for another environment");
    }
    Ok(Key::new(
        plain[16..32].try_into().unwrap(),
        plain[32..].try_into().unwrap(),
    ))
}

/// Opens each item under the environment key (SSM-SPEC-03 §10). Any failure fails the whole call.
pub fn decrypt_items(ek: &Key, exchange: &Value) -> Result<HashMap<String, String>, Error> {
    let b = &RustCrypto;
    let str_of = |v: &Value| {
        v.as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error("malformed exchange".into()))
    };
    let mut out = HashMap::new();
    for it in exchange["items"]
        .as_array()
        .ok_or_else(|| Error("malformed exchange".into()))?
    {
        let id = uuid(&str_of(&it["id"])?)?;
        let revision = it["revision"]
            .as_u64()
            .ok_or_else(|| Error("malformed exchange".into()))?;
        let ik = unwrap_key(
            b,
            ek,
            ObjectRef { id, revision: 0 },
            &b64(&str_of(&it["item_key"])?)?,
        )
        .map_err(decrypt_failed)?;
        let plain = open(
            b,
            &ik,
            ObjectRef { id, revision },
            &b64(&str_of(&it["payload"])?)?,
        )
        .map_err(decrypt_failed)?;
        let p: Value =
            serde_json::from_slice(&plain).map_err(|_| Error("malformed payload".into()))?;
        let name = p["name"].as_str().unwrap_or_default().to_owned();
        if out.contains_key(&name) {
            return err(format!(
                "two secrets are named {name:?}; rename one in the app"
            ));
        }
        out.insert(name, p["secret"].as_str().unwrap_or_default().to_owned());
    }
    Ok(out)
}

fn pin_of(spki_der: &[u8]) -> String {
    B64.encode(Sha256::digest(spki_der))
}

/// SEC-TLS-05: the identity key matches `pin`, signed the statement for this server, and attests `conn_pin`.
pub fn verify_attestation(
    a: &Value,
    pin: &str,
    server_id: &str,
    conn_pin: &str,
) -> Result<HashSet<String>, Error> {
    let field = |k: &str| {
        a[k].as_str()
            .ok_or_else(|| Error("malformed attestation".into()))
            .and_then(b64)
    };
    let (der, body, sig) = (
        field("identity_public_key")?,
        field("statement")?,
        field("signature")?,
    );
    let ok = pin_of(&der) == pin
        && VerifyingKey::from_public_key_der(&der)
            .ok()
            .zip(DerSignature::try_from(sig.as_slice()).ok())
            .is_some_and(|(k, s)| k.verify(&body, &s).is_ok());
    if !ok {
        return err("server identity does not match the pin");
    }
    let st: Value =
        serde_json::from_slice(&body).map_err(|_| Error("malformed attestation".into()))?;
    if st["purpose"] != "ssm-tls-attestation-v1" || st["server_id"] != server_id {
        return err("attestation is not for this server");
    }
    let pins: HashSet<String> = st["tls_pins"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p.as_str().map(str::to_owned))
        .collect();
    if !pins.contains(conn_pin) {
        return err("TLS certificate is not attested by the server identity");
    }
    Ok(pins)
}

/// Replaces CA and host name checks with the pin check (SEC-TLS-05). Signatures are still verified, so the server
/// must hold the pinned key.
#[derive(Debug)]
struct PinVerifier {
    allowed: Option<HashSet<String>>,
    seen: Mutex<Option<String>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use x509_cert::der::{Decode, Encode};
        let cert = x509_cert::Certificate::from_der(end_entity)
            .map_err(|_| rustls::Error::General("bad certificate".into()))?;
        let spki = cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|_| rustls::Error::General("bad certificate".into()))?;
        let pin = pin_of(&spki);
        let ok = self.allowed.as_ref().is_none_or(|a| a.contains(&pin));
        *self.seen.lock().unwrap() = Some(pin);
        if ok {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "ssm: server certificate is not pinned".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Returns an OIDC token for the audience (the server ID).
pub type Credential = Box<dyn FnMut(&str) -> Result<String, Error> + Send>;

/// Caches one environment's secrets in memory for the TTL (SDK-04); a revoked grant stops at the next refresh.
pub struct Client {
    host: String,
    port: u16,
    server_id: String,
    pin: String,
    environment_id: String,
    ci_key: Zeroizing<String>,
    ttl: Duration,
    credential: Credential,
    kind: &'static str,
    cloud: Option<Box<dyn cloud::Backend>>,
    pins: Option<HashSet<String>>,
    secrets: Option<(Instant, HashMap<String, String>)>,
}

impl Client {
    pub fn new(
        url: &str,
        server_id: &str,
        pin: &str,
        environment_id: &str,
        ci: &str,
    ) -> Result<Self, Error> {
        ci_key(ci)?;
        Self::base(url, server_id, pin, environment_id, ci, None)
    }

    /// A cloud workload (`cloud::Aws`, `cloud::Azure` or `cloud::Gcp`): no CI key (SEC-MACH-06/08/09).
    pub fn new_cloud(
        url: &str,
        server_id: &str,
        pin: &str,
        environment_id: &str,
        backend: Box<dyn cloud::Backend>,
    ) -> Result<Self, Error> {
        Self::base(url, server_id, pin, environment_id, "", Some(backend))
    }

    fn base(
        url: &str,
        server_id: &str,
        pin: &str,
        environment_id: &str,
        ci: &str,
        backend: Option<Box<dyn cloud::Backend>>,
    ) -> Result<Self, Error> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| Error("URL must be https://host[:port]".into()))?;
        let authority = rest.split('/').next().unwrap_or_default();
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
                (h, p.parse().map_err(|_| Error("bad port".into()))?)
            }
            _ => (authority, 443),
        };
        if host.is_empty() {
            return err("URL must be https://host[:port]");
        }
        if server_id.is_empty() || pin.is_empty() {
            return err("server ID and pin are required");
        }
        uuid(environment_id)?;
        Ok(Client {
            host: host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
            port,
            server_id: server_id.into(),
            pin: pin.into(),
            environment_id: environment_id.into(),
            ci_key: Zeroizing::new(ci.into()),
            ttl: Duration::from_secs(300),
            credential: Box::new(github_token),
            kind: "github",
            cloud: backend,
            pins: None,
            secrets: None,
        })
    }

    /// Reads `SSM_URL`, `SSM_SERVER_ID`, `SSM_PIN`, `SSM_ENVIRONMENT_ID` and `SSM_CI_KEY`; for cloud workloads
    /// `SSM_AWS_KMS_KEY`, `SSM_AZURE_KEY` (+ `SSM_AZURE_AUDIENCE`) or `SSM_GCP_KMS_KEY` instead of `SSM_CI_KEY` (SDK-09).
    pub fn from_env() -> Result<Self, Error> {
        let e = |k: &str| std::env::var(k).unwrap_or_default();
        let (url, sid, pin, env) = (
            e("SSM_URL"),
            e("SSM_SERVER_ID"),
            e("SSM_PIN"),
            e("SSM_ENVIRONMENT_ID"),
        );
        if let Some(b) = cloud::from_env()? {
            return Self::new_cloud(&url, &sid, &pin, &env, b);
        }
        let c = Self::new(&url, &sid, &pin, &env, &e("SSM_CI_KEY"))?;
        Ok(if e("GITLAB_CI") == "true" {
            c.gitlab()
        } else {
            c
        })
    }

    /// GitLab CI (SEC-MACH-07): the job's ID token from `SSM_ID_TOKEN` (declared with the server ID as `aud`).
    pub fn gitlab(mut self) -> Self {
        self.kind = "gitlab";
        self.credential = Box::new(gitlab_token);
        self
    }

    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn credential(
        mut self,
        f: impl FnMut(&str) -> Result<String, Error> + Send + 'static,
    ) -> Self {
        self.credential = Box::new(f);
        self
    }

    pub fn get(&mut self, name: &str) -> Result<String, Error> {
        self.all()?
            .remove(name)
            .ok_or_else(|| Error(format!("no secret named {name:?} in this environment")))
    }

    pub fn all(&mut self) -> Result<HashMap<String, String>, Error> {
        if self
            .secrets
            .as_ref()
            .is_none_or(|(t, _)| t.elapsed() >= self.ttl)
        {
            self.refresh()?;
        }
        Ok(self.secrets.as_ref().unwrap().1.clone())
    }

    fn refresh(&mut self) -> Result<(), Error> {
        if self.pins.is_none() {
            let (status, body, conn_pin) = self.request("GET", "/v1/tls/attestation", None)?;
            if status != 200 {
                return err("server has no valid TLS attestation");
            }
            let a: Value =
                serde_json::from_slice(&body).map_err(|_| Error("malformed attestation".into()))?;
            self.pins = Some(verify_attestation(
                &a,
                &self.pin,
                &self.server_id,
                &conn_pin,
            )?);
        }
        let (kind, cred) = match &self.cloud {
            Some(b) => (b.kind(), b.identity(&self.server_id)?),
            None => (self.kind, (self.credential)(&self.server_id)?),
        };
        let req = serde_json::json!({"environment_id": self.environment_id, "kind": kind, "credential": cred}).to_string();
        let (status, body, _) =
            match self.request("POST", "/v1/machine/exchange", Some(req.as_bytes())) {
                Ok(r) => r,
                Err(e) => {
                    self.pins = None; // the certificate may have rotated: attest again next time
                    return Err(e);
                }
            };
        if status != 200 {
            return err(format!("server refused this machine identity ({status})"));
        }
        let ex: Value =
            serde_json::from_slice(&body).map_err(|_| Error("malformed exchange".into()))?;
        let secrets = match &self.cloud {
            Some(b) => {
                let wk = b64(ex["wrapped_key"].as_str().unwrap_or_default())?;
                let plain = Zeroizing::new(b.decrypt(&wk)?);
                decrypt_items(&cloud_env_key(&plain, &self.environment_id)?, &ex)?
            }
            None => decrypt_exchange(&self.ci_key, &self.environment_id, &ex)?,
        };
        self.secrets = Some((Instant::now(), secrets));
        Ok(())
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>, String), Error> {
        pinned_request(
            &self.host,
            self.port,
            self.pins.as_ref(),
            method,
            path,
            body,
            None,
        )
    }
}

/// One request on a fresh TLS 1.3 connection, accepted only if the certificate's pin is in `pins` (or, with none yet,
/// any certificate: the caller then checks the attestation for the returned pin, SEC-TLS-05). Used by the CLI too.
/// ponytail: minimal HTTP/1.1 (Connection: close, Content-Length or chunked) to avoid an HTTP client dependency.
pub fn pinned_request(
    host: &str,
    port: u16,
    pins: Option<&HashSet<String>>,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    token: Option<&str>,
) -> Result<(u16, Vec<u8>, String), Error> {
    let io = |e: std::io::Error| Error(e.to_string());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinVerifier {
        allowed: pins.cloned(),
        seen: Mutex::new(None),
        provider: provider.clone(),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_owned()).map_err(|_| Error("bad host".into()))?;
    let conn = ClientConnection::new(Arc::new(config), name).map_err(|e| Error(e.to_string()))?;
    let tcp = TcpStream::connect((host, port)).map_err(io)?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(io)?;
    let mut tls = StreamOwned::new(conn, tcp);
    let body = body.unwrap_or_default();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\n\r\n",
        body.len()
    );
    tls.write_all(head.as_bytes())
        .and_then(|_| tls.write_all(body))
        .and_then(|_| tls.flush())
        .map_err(io)?;
    let conn_pin = verifier
        .seen
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| Error("no server certificate".into()))?;
    let mut r = BufReader::new(tls);
    let mut line = String::new();
    r.read_line(&mut line).map_err(io)?;
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error("bad HTTP response".into()))?;
    let (mut len, mut chunked) = (None, false);
    loop {
        line.clear();
        r.read_line(&mut line).map_err(io)?;
        let h = line.trim_end().to_ascii_lowercase();
        if h.is_empty() {
            break;
        }
        if let Some(v) = h.strip_prefix("content-length:") {
            len = v.trim().parse::<usize>().ok();
        }
        chunked |= h.starts_with("transfer-encoding:") && h.contains("chunked");
    }
    let mut out = Vec::new();
    if chunked {
        loop {
            line.clear();
            r.read_line(&mut line).map_err(io)?;
            let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or_default(), 16)
                .map_err(|_| Error("bad chunk".into()))?;
            if n == 0 {
                break;
            }
            let start = out.len();
            out.resize(start + n, 0);
            r.read_exact(&mut out[start..]).map_err(io)?;
            line.clear();
            r.read_line(&mut line).map_err(io)?;
        }
    } else if let Some(n) = len {
        out.resize(n, 0);
        r.read_exact(&mut out).map_err(io)?;
    } else {
        r.take(64 << 20).read_to_end(&mut out).map_err(io)?;
    }
    Ok((status, out, conn_pin))
}

/// The job's ID token, declared with the server ID as audience: `id_tokens: SSM_ID_TOKEN: aud: <server ID>`.
pub fn gitlab_token(_: &str) -> Result<String, Error> {
    match std::env::var("SSM_ID_TOKEN") {
        Ok(t) if !t.is_empty() => Ok(t),
        _ => err("SSM_ID_TOKEN is not set; declare it under id_tokens with the server ID as aud"),
    }
}

/// Asks the GitHub Actions runner for an OIDC token. The workflow needs `permissions: id-token: write`.
///
/// ponytail: shells out to curl (present on every GitHub runner) rather than adding a CA-verifying HTTP client.
pub fn github_token(audience: &str) -> Result<String, Error> {
    let (url, tok) = match (
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL"),
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    ) {
        (Ok(u), Ok(t)) if !u.is_empty() && !t.is_empty() => (u, t),
        _ => {
            return err(
                "not in GitHub Actions, or the workflow lacks `permissions: id-token: write`",
            );
        }
    };
    let aud: String = audience
        .bytes()
        .map(|c| {
            if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
                (c as char).to_string()
            } else {
                format!("%{c:02X}")
            }
        })
        .collect();
    let out = std::process::Command::new("curl")
        .args([
            "-sSf",
            "--max-time",
            "30",
            "-H",
            "@-",
            &format!("{url}&audience={aud}"),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin
                .take()
                .unwrap()
                .write_all(format!("Authorization: Bearer {tok}\n").as_bytes())?;
            c.wait_with_output()
        })
        .map_err(|e| Error(e.to_string()))?;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    match v["value"].as_str() {
        Some(s) if out.status.success() && !s.is_empty() => Ok(s.to_owned()),
        _ => err("GitHub did not issue an OIDC token"),
    }
}
