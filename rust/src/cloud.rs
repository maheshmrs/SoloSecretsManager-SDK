//! Cloud workload identities without cloud SDKs (SEC-MACH-06/08/09, SDK-09): a small SigV4 signer checked against
//! `testvectors/aws-sigv4.json`, the AWS credential chain, and the Azure and GCP metadata and KMS REST calls.

use crate::Error;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
use hmac::{KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const STS_BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";

/// Proves a cloud workload's identity and has its KMS decrypt the environment key.
pub trait Backend: Send {
    fn kind(&self) -> &'static str;
    fn identity(&self, server_id: &str) -> Result<String, Error>;
    fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, Error>;
}

fn err<T>(m: impl Into<String>) -> Result<T, Error> {
    Err(Error(m.into()))
}

pub(crate) fn http(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> Result<String, Error> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut req = ureq::http::Request::builder().method(method).uri(url);
    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("host") && !k.eq_ignore_ascii_case("content-length") {
            req = req.header(k.as_str(), v.as_str());
        }
    }
    let short = url.split('?').next().unwrap_or_default();
    let req = req
        .body(body.unwrap_or_default().to_owned())
        .map_err(|e| Error(e.to_string()))?;
    let mut resp = agent
        .run(req)
        .map_err(|e| Error(format!("{method} {short}: {e}")))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if status != 200 {
        return err(format!(
            "{method} {short}: {status} {}",
            text.chars().take(500).collect::<String>().trim()
        ));
    }
    Ok(text)
}

fn hmac(key: &[u8], s: &str) -> Vec<u8> {
    let mut m = hmac::Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    m.update(s.as_bytes());
    m.finalize().into_bytes().to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Clone, Debug)]
pub struct Credentials {
    pub key: String,
    pub secret: String,
    pub token: String,
}

/// UTC "YYYYMMDDTHHMMSSZ" for Unix seconds (civil-from-days, no date crate).
pub fn amz_date(unix: u64) -> String {
    let (days, secs) = ((unix / 86400) as i64, unix % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// The headers to send: the given ones plus Host, Content-Length, X-Amz-Date, the session token and Authorization.
/// Same canonical form as AWS's Go signer (content-length is signed).
#[allow(clippy::too_many_arguments)] // mirrors the SigV4 inputs
pub fn sigv4(
    method: &str,
    url: &str,
    region: &str,
    service: &str,
    headers: &[(&str, &str)],
    body: &str,
    c: &Credentials,
    amz: &str,
) -> Vec<(String, String)> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let (host, path_q) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
    let (path, query) = path_q.split_once('?').unwrap_or((path_q, ""));
    let mut h: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    h.push(("Host".into(), host.into()));
    h.push(("Content-Length".into(), body.len().to_string()));
    h.push(("X-Amz-Date".into(), amz.into()));
    if !c.token.is_empty() {
        h.push(("X-Amz-Security-Token".into(), c.token.clone()));
    }
    let canon: BTreeMap<String, String> = h
        .iter()
        .map(|(k, v)| {
            (
                k.to_ascii_lowercase(),
                v.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    let signed = canon.keys().cloned().collect::<Vec<_>>().join(";");
    let ch: String = canon.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let creq = [
        method,
        &format!("/{path}"),
        query,
        &ch,
        &signed,
        &hex(&Sha256::digest(body)),
    ]
    .join("\n");
    let day = &amz[..8];
    let scope = format!("{day}/{region}/{service}/aws4_request");
    let sts = ["AWS4-HMAC-SHA256", amz, &scope, &hex(&Sha256::digest(creq))].join("\n");
    let mut k = format!("AWS4{}", c.secret).into_bytes();
    for part in [day, region, service, "aws4_request"] {
        k = hmac(&k, part);
    }
    h.push((
        "Authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={}",
            c.key,
            hex(&hmac(&k, &sts))
        ),
    ));
    h
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}

fn jstr(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or_default().to_owned()
}

/// Environment, web identity (EKS IRSA), container (ECS, EKS Pod Identity), then EC2 IMDSv2 (SDK-09).
pub fn aws_credentials() -> Result<Credentials, Error> {
    if !env("AWS_ACCESS_KEY_ID").is_empty() && !env("AWS_SECRET_ACCESS_KEY").is_empty() {
        return Ok(Credentials {
            key: env("AWS_ACCESS_KEY_ID"),
            secret: env("AWS_SECRET_ACCESS_KEY"),
            token: env("AWS_SESSION_TOKEN"),
        });
    }
    let parse = |s: String| {
        serde_json::from_str::<Value>(&s)
            .map_err(|_| Error("unexpected AWS credentials answer".into()))
    };
    let c = if !env("AWS_WEB_IDENTITY_TOKEN_FILE").is_empty() && !env("AWS_ROLE_ARN").is_empty() {
        let tok = std::fs::read_to_string(env("AWS_WEB_IDENTITY_TOKEN_FILE"))
            .map_err(|e| Error(e.to_string()))?;
        let enc = |s: &str| {
            s.bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect::<String>()
        };
        let session = if env("AWS_ROLE_SESSION_NAME").is_empty() {
            "ssm-sdk".into()
        } else {
            env("AWS_ROLE_SESSION_NAME")
        };
        let q = format!(
            "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn={}&RoleSessionName={}&WebIdentityToken={}",
            enc(&env("AWS_ROLE_ARN")),
            enc(&session),
            enc(tok.trim())
        );
        let sts = [env("AWS_ENDPOINT_URL_STS"), env("AWS_ENDPOINT_URL")]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or("https://sts.amazonaws.com".into());
        let x = parse(http(
            "POST",
            &format!("{}/", sts.trim_end_matches('/')),
            &[
                (
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
                ("Accept".into(), "application/json".into()),
            ],
            Some(&q),
        )?)?;
        let c = &x["AssumeRoleWithWebIdentityResponse"]["AssumeRoleWithWebIdentityResult"]["Credentials"];
        return Ok(Credentials {
            key: jstr(c, "AccessKeyId"),
            secret: jstr(c, "SecretAccessKey"),
            token: jstr(c, "SessionToken"),
        });
    } else if !env("AWS_CONTAINER_CREDENTIALS_FULL_URI").is_empty()
        || !env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").is_empty()
    {
        let mut hdr = vec![];
        if !env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE").is_empty() {
            let t = std::fs::read_to_string(env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"))
                .map_err(|e| Error(e.to_string()))?;
            hdr.push(("Authorization".to_owned(), t.trim().to_owned()));
        } else if !env("AWS_CONTAINER_AUTHORIZATION_TOKEN").is_empty() {
            hdr.push((
                "Authorization".to_owned(),
                env("AWS_CONTAINER_AUTHORIZATION_TOKEN"),
            ));
        }
        let u = if env("AWS_CONTAINER_CREDENTIALS_FULL_URI").is_empty() {
            format!(
                "http://169.254.170.2{}",
                env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
            )
        } else {
            env("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        };
        parse(http("GET", &u, &hdr, None)?)?
    } else {
        let imds = "http://169.254.169.254";
        let t = http(
            "PUT",
            &format!("{imds}/latest/api/token"),
            &[("X-aws-ec2-metadata-token-ttl-seconds".into(), "300".into())],
            Some(""),
        )?;
        let th = [("X-aws-ec2-metadata-token".to_owned(), t)];
        let roles = http(
            "GET",
            &format!("{imds}/latest/meta-data/iam/security-credentials/"),
            &th,
            None,
        )?;
        let role = roles.split_whitespace().next().unwrap_or_default();
        parse(http(
            "GET",
            &format!("{imds}/latest/meta-data/iam/security-credentials/{role}"),
            &th,
            None,
        )?)?
    };
    Ok(Credentials {
        key: jstr(&c, "AccessKeyId"),
        secret: jstr(&c, "SecretAccessKey"),
        token: jstr(&c, "Token"),
    })
}

fn now_amz() -> String {
    amz_date(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

pub struct Aws {
    pub(crate) key_arn: String,
    pub(crate) region: String,
    pub(crate) sts: String,
    pub(crate) kms: String,
}

impl Aws {
    pub fn new(key_arn: &str, sts_endpoint: &str) -> Result<Self, Error> {
        let p: Vec<&str> = key_arn.split(':').collect();
        if p.len() < 6 || p[2] != "kms" || p[3].is_empty() {
            return err("SSM_AWS_KMS_KEY must be a KMS key ARN");
        }
        let kms = [env("AWS_ENDPOINT_URL_KMS"), env("AWS_ENDPOINT_URL")]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or(format!("https://kms.{}.amazonaws.com", p[3]));
        Ok(Aws {
            key_arn: key_arn.into(),
            region: p[3].into(),
            sts: if sts_endpoint.is_empty() {
                "https://sts.amazonaws.com"
            } else {
                sts_endpoint
            }
            .trim_end_matches('/')
            .into(),
            kms: kms.trim_end_matches('/').into(),
        })
    }
}

impl Backend for Aws {
    fn kind(&self) -> &'static str {
        "aws"
    }

    fn identity(&self, server_id: &str) -> Result<String, Error> {
        let host = self
            .sts
            .split("://")
            .nth(1)
            .unwrap_or_default()
            .split(['/', ':'])
            .next()
            .unwrap_or_default();
        let parts: Vec<&str> = host.split('.').collect();
        let region = if host.starts_with("sts.") && parts.len() == 4 {
            parts[1]
        } else {
            "us-east-1"
        };
        let url = format!("{}/", self.sts);
        let h = sigv4(
            "POST",
            &url,
            region,
            "sts",
            &[
                (
                    "Content-Type",
                    "application/x-www-form-urlencoded; charset=utf-8",
                ),
                ("X-Ssm-Server-Id", server_id),
            ],
            STS_BODY,
            &aws_credentials()?,
            &now_amz(),
        );
        let headers: serde_json::Map<String, Value> = h
            .into_iter()
            .filter(|(k, _)| k != "Host" && k != "Content-Length")
            .map(|(k, v)| (k, Value::String(v)))
            .collect();
        Ok(B64URL.encode(
            json!({"method": "POST", "url": url, "headers": headers, "body": STS_BODY}).to_string(),
        ))
    }

    fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, Error> {
        let body = json!({"KeyId": self.key_arn, "CiphertextBlob": B64STD.encode(blob), "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"}).to_string();
        let url = format!("{}/", self.kms);
        let h = sigv4(
            "POST",
            &url,
            &self.region,
            "kms",
            &[
                ("Content-Type", "application/x-amz-json-1.1"),
                ("X-Amz-Target", "TrentService.Decrypt"),
            ],
            &body,
            &aws_credentials()?,
            &now_amz(),
        );
        let x = http("POST", &url, &h, Some(&body)).map_err(|e| {
            Error(format!(
                "KMS refused to decrypt the environment key: {}",
                e.0
            ))
        })?;
        let v: Value = serde_json::from_str(&x).unwrap_or_default();
        B64STD
            .decode(v["Plaintext"].as_str().unwrap_or_default())
            .map_err(|_| Error("unexpected KMS answer".into()))
    }
}

pub struct Azure {
    pub(crate) key_url: String,
    pub(crate) audience: String,
    pub(crate) imds: String,
}

impl Azure {
    pub fn new(key_url: &str, audience: &str) -> Result<Self, Error> {
        if !key_url.starts_with("https://") || !key_url.contains("/keys/") {
            return err(
                "SSM_AZURE_KEY must be a Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>/<version>)",
            );
        }
        if audience.is_empty() {
            return err(
                "SSM_AZURE_AUDIENCE is required (the application ID URI registered for the server)",
            );
        }
        Ok(Azure {
            key_url: key_url.trim_end_matches('/').into(),
            audience: audience.into(),
            imds: "http://169.254.169.254".into(),
        })
    }

    fn token(&self, resource: &str) -> Result<String, Error> {
        let enc: String = resource
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        let x = if !env("IDENTITY_ENDPOINT").is_empty() && !env("IDENTITY_HEADER").is_empty() {
            http(
                "GET",
                &format!(
                    "{}?api-version=2019-08-01&resource={enc}",
                    env("IDENTITY_ENDPOINT")
                ),
                &[("X-IDENTITY-HEADER".into(), env("IDENTITY_HEADER"))],
                None,
            )?
        } else {
            http(
                "GET",
                &format!(
                    "{}/metadata/identity/oauth2/token?api-version=2018-02-01&resource={enc}",
                    self.imds
                ),
                &[("Metadata".into(), "true".into())],
                None,
            )?
        };
        let v: Value = serde_json::from_str(&x).unwrap_or_default();
        match v["access_token"].as_str() {
            Some(t) if !t.is_empty() => Ok(t.into()),
            _ => err("Azure managed identity returned no token"),
        }
    }
}

impl Azure {
    /// Points at other endpoints (tests, sovereign clouds).
    pub fn set_endpoints(&mut self, imds: &str, key_url: &str) {
        (self.imds, self.key_url) = (imds.into(), key_url.into());
    }
}

impl Backend for Azure {
    fn kind(&self) -> &'static str {
        "azure"
    }

    fn identity(&self, _: &str) -> Result<String, Error> {
        self.token(&self.audience)
    }

    fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, Error> {
        let body = json!({"alg": "RSA-OAEP-256", "value": B64URL.encode(blob)}).to_string();
        let tok = self.token("https://vault.azure.net")?;
        let x = http(
            "POST",
            &format!("{}/decrypt?api-version=7.4", self.key_url),
            &[
                ("Authorization".into(), format!("Bearer {tok}")),
                ("Content-Type".into(), "application/json".into()),
            ],
            Some(&body),
        )
        .map_err(|e| {
            Error(format!(
                "Key Vault refused to decrypt the environment key: {}",
                e.0
            ))
        })?;
        let v: Value = serde_json::from_str(&x).unwrap_or_default();
        B64URL
            .decode(
                v["value"]
                    .as_str()
                    .unwrap_or_default()
                    .trim_end_matches('='),
            )
            .map_err(|_| Error("unexpected Key Vault answer".into()))
    }
}

const SA: &str = "/computeMetadata/v1/instance/service-accounts/default/";

pub struct Gcp {
    pub(crate) key_version: String,
    pub(crate) metadata: String,
    pub(crate) km: String,
}

impl Gcp {
    pub fn new(key_version: &str) -> Result<Self, Error> {
        if !key_version.starts_with("projects/") || !key_version.contains("/cryptoKeyVersions/") {
            return err(
                "SSM_GCP_KMS_KEY must be a key version name (projects/…/cryptoKeys/…/cryptoKeyVersions/N)",
            );
        }
        Ok(Gcp {
            key_version: key_version.into(),
            metadata: "http://metadata.google.internal".into(),
            km: "https://cloudkms.googleapis.com".into(),
        })
    }
}

impl Gcp {
    /// Points at other endpoints (tests, private service connect).
    pub fn set_endpoints(&mut self, metadata: &str, km: &str) {
        (self.metadata, self.km) = (metadata.into(), km.into());
    }
}

impl Backend for Gcp {
    fn kind(&self) -> &'static str {
        "gcp"
    }

    fn identity(&self, server_id: &str) -> Result<String, Error> {
        let aud: String = server_id
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        Ok(http(
            "GET",
            &format!("{}{SA}identity?format=full&audience={aud}", self.metadata),
            &[("Metadata-Flavor".into(), "Google".into())],
            None,
        )?
        .trim()
        .into())
    }

    fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, Error> {
        let at: Value = serde_json::from_str(&http(
            "GET",
            &format!("{}{SA}token", self.metadata),
            &[("Metadata-Flavor".into(), "Google".into())],
            None,
        )?)
        .unwrap_or_default();
        let x = http(
            "POST",
            &format!("{}/v1/{}:asymmetricDecrypt", self.km, self.key_version),
            &[
                (
                    "Authorization".into(),
                    format!("Bearer {}", jstr(&at, "access_token")),
                ),
                ("Content-Type".into(), "application/json".into()),
            ],
            Some(&json!({"ciphertext": B64STD.encode(blob)}).to_string()),
        )
        .map_err(|e| {
            Error(format!(
                "Cloud KMS refused to decrypt the environment key: {}",
                e.0
            ))
        })?;
        let v: Value = serde_json::from_str(&x).unwrap_or_default();
        B64STD
            .decode(v["plaintext"].as_str().unwrap_or_default())
            .map_err(|_| Error("unexpected Cloud KMS answer".into()))
    }
}

/// `SSM_AWS_KMS_KEY`, `SSM_AZURE_KEY` (+ `SSM_AZURE_AUDIENCE`) or `SSM_GCP_KMS_KEY`; `None` for the CI-key kinds.
pub fn from_env() -> Result<Option<Box<dyn Backend>>, Error> {
    Ok(if !env("SSM_AWS_KMS_KEY").is_empty() {
        Some(Box::new(Aws::new(
            &env("SSM_AWS_KMS_KEY"),
            &env("SSM_AWS_STS_ENDPOINT"),
        )?))
    } else if !env("SSM_AZURE_KEY").is_empty() {
        Some(Box::new(Azure::new(
            &env("SSM_AZURE_KEY"),
            &env("SSM_AZURE_AUDIENCE"),
        )?))
    } else if !env("SSM_GCP_KMS_KEY").is_empty() {
        Some(Box::new(Gcp::new(&env("SSM_GCP_KMS_KEY"))?))
    } else {
        None
    })
}
