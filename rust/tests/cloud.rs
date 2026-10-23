//! SDK-09: SigV4 matches AWS's Go signer; Azure/GCP REST calls; AWS against floci (SSM_TEST_FLOCI=1).

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64STD, URL_SAFE_NO_PAD as B64URL};
use serde_json::{Value, json};
use solosecretsmanager::cloud::{self, Backend, Credentials};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const PLAIN: &[u8] = b"environment-id-key-id-and-key-bytes-sixty-four-bytes-long......";

#[test]
fn sigv4_vectors() {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testvectors/aws-sigv4.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let c = Credentials {
        key: v["access_key_id"].as_str().unwrap().into(),
        secret: v["secret_access_key"].as_str().unwrap().into(),
        token: v["session_token"].as_str().unwrap().into(),
    };
    let amz = v["time"].as_str().unwrap().replace(['-', ':'], "");
    for t in v["cases"].as_array().unwrap() {
        let hdr: Vec<(&str, &str)> = t["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str().unwrap()))
            .collect();
        let s = |k: &str| t[k].as_str().unwrap();
        let h = cloud::sigv4(
            s("method"),
            s("url"),
            s("region"),
            s("service"),
            &hdr,
            s("body"),
            &c,
            &amz,
        );
        for (k, want) in t["signed"].as_object().unwrap() {
            assert_eq!(
                h.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()),
                want.as_str(),
                "{}: {k}",
                t["name"]
            );
        }
    }
    assert_eq!(cloud::amz_date(1_792_112_523), "20261016T010203Z");
    assert_eq!(cloud::amz_date(951_782_400), "20000229T000000Z");
}

#[test]
fn cloud_env_key() {
    let env = "e0e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0";
    let mut good = vec![0xe0u8; 16];
    good.extend(0u8..48);
    assert_eq!(
        solosecretsmanager::cloud_env_key(&good, env).unwrap().id[15],
        15
    );
    assert!(
        solosecretsmanager::cloud_env_key(&good, "e1e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0").is_err()
    );
}

/// A plain-HTTP fake for IMDS, Key Vault, the GCP metadata server and Cloud KMS. "Decrypting" maps the test blob back
/// to PLAIN; real RSA is the cloud KMS's job.
fn fake() -> (String, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut r = BufReader::new(s.try_clone().unwrap());
            let (mut first, mut line, mut hdr, mut len) =
                (String::new(), String::new(), vec![], 0usize);
            r.read_line(&mut first).unwrap();
            while r.read_line(&mut line).is_ok() && line.trim() != "" {
                let l = line.trim().to_owned();
                if let Some(n) = l.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = n.trim().parse().unwrap_or(0);
                }
                hdr.push(l);
                line.clear();
            }
            let mut b = vec![0; len];
            r.read_exact(&mut b).unwrap();
            let path = first
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            s2.lock().unwrap().push(path.clone());
            let has = |h: &str| hdr.iter().any(|x| x.eq_ignore_ascii_case(h));
            let body: Value = serde_json::from_slice(&b).unwrap_or_default();
            let q = |k: &str| {
                path.split(['?', '&'])
                    .find_map(|p| p.strip_prefix(&format!("{k}=")))
                    .unwrap_or_default()
                    .to_owned()
            };
            let out = if path.starts_with("/metadata/identity/oauth2/token")
                && has("Metadata: true")
            {
                Some(json!({"access_token": format!("az-{}", q("resource").replace("%3A", ":").replace("%2F", "/"))}).to_string())
            } else if path.contains("/identity?") && has("Metadata-Flavor: Google") {
                Some(format!("gcp-{}-{}", q("audience"), q("format")))
            } else if path.ends_with("/token") && has("Metadata-Flavor: Google") {
                Some(json!({"access_token": "gcp-at"}).to_string())
            } else if path.contains("/decrypt?")
                && has("Authorization: Bearer az-https://vault.azure.net")
                && body["alg"] == "RSA-OAEP-256"
                && body["value"] == B64URL.encode(b"blob")
            {
                Some(json!({"value": B64URL.encode(PLAIN)}).to_string())
            } else if path.ends_with(":asymmetricDecrypt")
                && has("Authorization: Bearer gcp-at")
                && body["ciphertext"] == B64STD.encode(b"blob")
            {
                Some(json!({"plaintext": B64STD.encode(PLAIN)}).to_string())
            } else {
                None
            };
            let (code, o) = out.map_or((403, String::new()), |o| (200, o));
            let _ = write!(
                s,
                "HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{o}",
                o.len()
            );
        }
    });
    (base, seen)
}

#[test]
fn azure_and_gcp() {
    let (base, seen) = fake();
    let mut az =
        cloud::Azure::new("https://v.vault.azure.net/keys/ssm/1", "api://ssm-vault").unwrap();
    az.set_endpoints(&base, &format!("{base}/keys/ssm/1"));
    assert_eq!(az.identity("vault.test").unwrap(), "az-api://ssm-vault"); // the registered audience, not the server ID
    assert_eq!(az.decrypt(b"blob").unwrap(), PLAIN);
    let mut g = cloud::Gcp::new(
        "projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1",
    )
    .unwrap();
    g.set_endpoints(&base, &base);
    assert_eq!(g.identity("vault.test").unwrap(), "gcp-vault.test-full");
    assert_eq!(g.decrypt(b"blob").unwrap(), PLAIN);
    assert!(seen.lock().unwrap().iter().any(|p| p == "/v1/projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1:asymmetricDecrypt"));
    assert!(cloud::Azure::new("http://v/keys/k", "a").is_err());
    assert!(cloud::Azure::new("https://v.vault.azure.net/keys/k/1", "").is_err());
    assert!(cloud::Gcp::new("k").is_err());
    assert!(cloud::Aws::new("x", "").is_err());
}

#[test]
fn aws_against_floci() {
    if std::env::var_os("SSM_TEST_FLOCI").is_none() {
        return; // needs floci running
    }
    let ep = "http://localhost:4566";
    let aws = |args: &[&str]| {
        let o = std::process::Command::new("aws")
            .args(["--endpoint-url", ep, "--output", "text"])
            .args(args)
            .env("AWS_ACCESS_KEY_ID", "test")
            .env("AWS_SECRET_ACCESS_KEY", "test")
            .env("AWS_DEFAULT_REGION", "us-east-1")
            .output()
            .unwrap();
        assert!(o.status.success(), "{args:?}");
        String::from_utf8(o.stdout).unwrap().trim().to_owned()
    };
    let arn = aws(&[
        "kms",
        "create-key",
        "--key-spec",
        "RSA_2048",
        "--key-usage",
        "ENCRYPT_DECRYPT",
        "--query",
        "KeyMetadata.Arn",
    ]);
    let pub_der = B64STD
        .decode(aws(&[
            "kms",
            "get-public-key",
            "--key-id",
            &arn,
            "--query",
            "PublicKey",
        ]))
        .unwrap();
    // Encrypt with the AWS CLI (RSAES_OAEP_SHA_256), as the app's wrap is the core's job.
    std::fs::write(std::env::temp_dir().join("ssm-rs-plain"), PLAIN).unwrap();
    let blob = B64STD
        .decode(aws(&[
            "kms",
            "encrypt",
            "--key-id",
            &arn,
            "--encryption-algorithm",
            "RSAES_OAEP_SHA_256",
            "--plaintext",
            &format!(
                "fileb://{}",
                std::env::temp_dir().join("ssm-rs-plain").display()
            ),
            "--query",
            "CiphertextBlob",
        ]))
        .unwrap();
    assert!(!pub_der.is_empty());
    // SAFETY: this test is the only one that touches these variables.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        std::env::set_var("AWS_ENDPOINT_URL", ep);
    }
    let a = cloud::Aws::new(&arn, ep).unwrap();
    let proof: Value =
        serde_json::from_slice(&B64URL.decode(a.identity("vault.test").unwrap()).unwrap()).unwrap();
    assert!(
        proof["headers"]["Authorization"]
            .as_str()
            .unwrap()
            .contains("x-ssm-server-id")
    );
    let hdr: Vec<(String, String)> = proof["headers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
        .collect();
    assert!(cloud_http(ep, &hdr, proof["body"].as_str().unwrap()).contains("<Arn>"));
    assert_eq!(a.decrypt(&blob).unwrap(), PLAIN);
}

fn cloud_http(ep: &str, hdr: &[(String, String)], body: &str) -> String {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut req = ureq::http::Request::builder()
        .method("POST")
        .uri(format!("{ep}/"));
    for (k, v) in hdr {
        req = req.header(k.as_str(), v.as_str());
    }
    agent
        .run(req.body(body.to_owned()).unwrap())
        .unwrap()
        .body_mut()
        .read_to_string()
        .unwrap()
}
