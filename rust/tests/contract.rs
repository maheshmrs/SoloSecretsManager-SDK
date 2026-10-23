//! QA-G-03 contract plus an end-to-end run against a fake TLS server.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use p256::pkcs8::EncodePublicKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use solosecretsmanager::{Client, decrypt_exchange, verify_attestation};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn vectors() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testvectors/machine-v1.json"
        ))
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn contract() {
    let v = vectors();
    let got = decrypt_exchange(
        v["ci_key"].as_str().unwrap(),
        v["environment_id"].as_str().unwrap(),
        &v["exchange"],
    )
    .unwrap();
    assert_eq!(serde_json::to_value(got).unwrap(), v["expected"]);
    let rejects = v["reject"].as_array().unwrap();
    assert!(rejects.len() >= 10);
    for r in rejects {
        assert!(
            decrypt_exchange(
                r["ci_key"].as_str().unwrap(),
                r["environment_id"].as_str().unwrap(),
                &r["exchange"]
            )
            .is_err(),
            "{}",
            r["name"]
        );
    }
    let a = &v["attestation"];
    let s = |c: &Value, k: &str| c[k].as_str().unwrap().to_owned();
    let pins = verify_attestation(
        &a["attestation"],
        &s(a, "pin"),
        &s(a, "server_id"),
        &s(a, "conn_pin"),
    )
    .unwrap();
    assert_eq!(
        pins,
        a["pins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_owned())
            .collect::<HashSet<_>>()
    );
    for r in v["attestation_reject"].as_array().unwrap() {
        assert!(
            verify_attestation(
                &r["attestation"],
                &s(r, "pin"),
                &s(r, "server_id"),
                &s(r, "conn_pin")
            )
            .is_err(),
            "{}",
            r["name"]
        );
    }
}

struct Fake {
    url: String,
    pin: String,
    calls: Arc<AtomicUsize>,
}

fn fake(server_id: &'static str, attest_own_cert: bool) -> Fake {
    let v = vectors();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pin = if attest_own_cert {
        {
            use x509_cert::der::{Decode, Encode};
            let c = x509_cert::Certificate::from_der(cert.cert.der()).unwrap();
            B64.encode(Sha256::digest(
                c.tbs_certificate()
                    .subject_public_key_info()
                    .to_der()
                    .unwrap(),
            ))
        }
    } else {
        "someone-else".into()
    };
    let id = SigningKey::from_slice(&[7; 32]).unwrap();
    let der = id.verifying_key().to_public_key_der().unwrap();
    let body = json!({"purpose": "ssm-tls-attestation-v1", "server_id": server_id, "tls_pins": [cert_pin]}).to_string();
    let sig: DerSignature = id.sign(body.as_bytes());
    let attestation = json!({"identity_public_key": B64.encode(der.as_bytes()), "statement": B64.encode(&body), "signature": B64.encode(sig.as_bytes())}).to_string();
    let exchange = v["exchange"].to_string();
    let env = v["environment_id"].clone();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
        )
        .unwrap(),
    );
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("https://127.0.0.1:{}", l.local_addr().unwrap().port());
    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = calls.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let Ok(conn) = rustls::ServerConnection::new(config.clone()) else {
                continue;
            };
            let mut tls = rustls::StreamOwned::new(conn, s);
            let mut r = BufReader::new(&mut tls);
            let (mut first, mut line, mut len) = (String::new(), String::new(), 0usize);
            if r.read_line(&mut first).is_err() {
                continue;
            }
            while r.read_line(&mut line).is_ok() && line.trim() != "" {
                if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = n.trim().parse().unwrap_or(0);
                }
                line.clear();
            }
            let mut b = vec![0; len];
            let _ = r.read_exact(&mut b);
            let (status, resp) = if first.starts_with("GET /v1/tls/attestation") {
                (200, attestation.clone())
            } else {
                c2.fetch_add(1, Ordering::SeqCst);
                let q: Value = serde_json::from_slice(&b).unwrap_or_default();
                if q["environment_id"] == env
                    && q["kind"] == "github"
                    && q["credential"] == format!("jwt-for-{server_id}")
                {
                    (200, exchange.clone())
                } else {
                    (401, String::new())
                }
            };
            let _ = write!(
                tls,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                resp.len()
            );
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    Fake {
        url,
        pin: B64.encode(Sha256::digest(der.as_bytes())),
        calls,
    }
}

#[test]
fn end_to_end() {
    let v = vectors();
    let (env, ci) = (
        v["environment_id"].as_str().unwrap(),
        v["ci_key"].as_str().unwrap(),
    );
    let cred = |aud: &str| Ok(format!("jwt-for-{aud}"));
    let s = fake("vault.test", true);
    let mut c = Client::new(&s.url, "vault.test", &s.pin, env, ci)
        .unwrap()
        .credential(cred)
        .ttl(std::time::Duration::from_secs(3600));
    assert_eq!(c.get("DATABASE_PASSWORD").unwrap(), "hunter2");
    assert!(c.get("NOPE").is_err());
    assert_eq!(s.calls.load(Ordering::SeqCst), 1); // cached
    for (sid, pin) in [("vault.test", "AAAA"), ("other", s.pin.as_str())] {
        assert!(
            Client::new(&s.url, sid, pin, env, ci)
                .unwrap()
                .credential(cred)
                .get("DATABASE_PASSWORD")
                .is_err(),
            "{sid}"
        );
    }
    let bad = fake("vault.test", false);
    assert!(
        Client::new(&bad.url, "vault.test", &bad.pin, env, ci)
            .unwrap()
            .credential(cred)
            .get("DATABASE_PASSWORD")
            .is_err()
    );
    assert!(Client::new("http://x", "s", "p", env, ci).is_err());
}
