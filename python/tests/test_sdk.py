"""QA-G-03 contract plus an end-to-end run against a fake TLS server. Run: python3 -m unittest discover -s tests"""

import datetime
import hashlib
import http.server
import json
import pathlib
import ssl
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "src"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import solosecretsmanager as ssm

V = json.loads((pathlib.Path(__file__).parents[2] / "testvectors/machine-v1.json").read_text())


class Contract(unittest.TestCase):
    def test_accept(self):
        self.assertEqual(ssm.decrypt_exchange(V["ci_key"], V["environment_id"], V["exchange"]), V["expected"])

    def test_reject(self):
        self.assertGreaterEqual(len(V["reject"]), 10)
        for r in V["reject"]:
            with self.subTest(r["name"]), self.assertRaises(ssm.SSMError):
                ssm.decrypt_exchange(r["ci_key"], r["environment_id"], r["exchange"])

    def test_attestation(self):
        a = V["attestation"]
        self.assertEqual(ssm.verify_attestation(a["attestation"], a["pin"], a["server_id"], a["conn_pin"]), set(a["pins"]))
        for r in V["attestation_reject"]:
            with self.subTest(r["name"]), self.assertRaises(ssm.SSMError):
                ssm.verify_attestation(r["attestation"], r["pin"], r["server_id"], r["conn_pin"])


def b64(b):
    return ssm._b64e(b)


class FakeServer:
    """Serves a signed attestation for its own certificate (or another pin) and the contract's exchange."""

    def __init__(self, server_id, attest_own_cert=True):
        tls_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(tls_key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).sign(tls_key, hashes.SHA256()))
        self.dir = tempfile.TemporaryDirectory()
        cf, kf = f"{self.dir.name}/c.pem", f"{self.dir.name}/k.pem"
        pathlib.Path(cf).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        pathlib.Path(kf).write_bytes(tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ident = ec.generate_private_key(ec.SECP256R1())
        der = ident.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.pin = b64(hashlib.sha256(der).digest())
        cert_pin = ssm._spki_pin(cert.public_bytes(serialization.Encoding.DER)) if attest_own_cert else "someone-else"
        body = json.dumps({"purpose": "ssm-tls-attestation-v1", "server_id": server_id, "tls_pins": [cert_pin]}).encode()
        attestation = json.dumps({"identity_public_key": b64(der), "statement": b64(body),
                                  "signature": b64(ident.sign(body, ec.ECDSA(hashes.SHA256())))}).encode()
        self.calls = 0
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, data=b""):
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self.reply(200, attestation) if self.path == "/v1/tls/attestation" else self.reply(404)

            def do_POST(self):
                outer.calls += 1
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                ok = req == {"environment_id": V["environment_id"], "kind": "github", "credential": "jwt-for-" + server_id}
                self.reply(200, json.dumps(V["exchange"]).encode()) if ok else self.reply(401)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf, kf)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.dir.cleanup()


def cred(aud):
    return "jwt-for-" + aud


class EndToEnd(unittest.TestCase):
    def test_client(self):
        s = FakeServer("vault.test")
        self.addCleanup(s.close)
        c = ssm.Client(s.url, "vault.test", s.pin, V["environment_id"], V["ci_key"], ttl=3600, credential=cred)
        self.assertEqual(c.get("DATABASE_PASSWORD"), "hunter2")
        with self.assertRaises(ssm.SSMError):
            c.get("NOPE")
        self.assertEqual(s.calls, 1)  # cached

        for name, (sid, pin) in {"wrong pin": ("vault.test", "AAAA"), "wrong server ID": ("other", s.pin)}.items():
            with self.subTest(name), self.assertRaises(ssm.SSMError):
                ssm.Client(s.url, sid, pin, V["environment_id"], V["ci_key"], credential=cred).get("DATABASE_PASSWORD")

        bad = FakeServer("vault.test", attest_own_cert=False)
        self.addCleanup(bad.close)
        with self.assertRaises(ssm.SSMError):
            ssm.Client(bad.url, "vault.test", bad.pin, V["environment_id"], V["ci_key"], credential=cred).get("DATABASE_PASSWORD")
        with self.assertRaises(ssm.SSMError):
            ssm.Client("http://x", "s", "p", V["environment_id"], V["ci_key"])


if __name__ == "__main__":
    unittest.main()
