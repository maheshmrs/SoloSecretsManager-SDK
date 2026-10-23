"""SDK-09: SigV4 matches AWS's Go signer; Azure/GCP REST calls; AWS against floci (SSM_TEST_FLOCI=1)."""

import base64
import datetime
import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import unittest
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "src"))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import solosecretsmanager as ssm
from solosecretsmanager import cloud

ROOT = pathlib.Path(__file__).parents[2]
SIG = json.loads((ROOT / "testvectors/aws-sigv4.json").read_text())
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PLAIN = b"environment-id-key-id-and-key-bytes-sixty-four-bytes-long......"


class SigV4(unittest.TestCase):
    def test_vectors(self):
        creds = {"key": SIG["access_key_id"], "secret": SIG["secret_access_key"], "token": SIG["session_token"]}
        now = datetime.datetime.fromisoformat(SIG["time"].replace("Z", "+00:00"))
        for c in SIG["cases"]:
            with self.subTest(c["name"]):
                h = cloud.sigv4(c["method"], c["url"], c["region"], c["service"], c["headers"], c["body"], creds, now)
                for k, v in c["signed"].items():
                    self.assertEqual(h[k], v, k)

    def test_cloud_env_key(self):
        env = "e0e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0"
        good = bytes.fromhex(env.replace("-", "")) + bytes(range(48))
        self.assertEqual(ssm.cloud_env_key(good, env), (bytes(range(16)), bytes(range(16, 48))))
        with self.assertRaises(ssm.SSMError):
            ssm.cloud_env_key(good, "e1e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0")


class AzureGCP(unittest.TestCase):
    def test_backends(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        blob = key.public_key().encrypt(PLAIN, OAEP)
        seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, obj, raw=False):
                b = obj if raw else json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                q = urllib.parse.parse_qs(u.query)
                seen.append(self.path)
                if u.path == "/metadata/identity/oauth2/token" and self.headers["Metadata"] == "true":
                    return self.reply({"access_token": "az-" + q["resource"][0]})
                if u.path.endswith("/identity") and self.headers["Metadata-Flavor"] == "Google":
                    return self.reply(f"gcp-{q['audience'][0]}-{q['format'][0]}".encode(), raw=True)
                if u.path.endswith("/token") and self.headers["Metadata-Flavor"] == "Google":
                    return self.reply({"access_token": "gcp-at"})
                self.send_response(403)
                self.end_headers()

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append(self.path)
                if self.path.endswith("/decrypt?api-version=7.4") and self.headers["Authorization"] == "Bearer az-https://vault.azure.net" \
                        and body["alg"] == "RSA-OAEP-256":
                    ct = base64.urlsafe_b64decode(body["value"] + "=" * (-len(body["value"]) % 4))
                    return self.reply({"value": base64.urlsafe_b64encode(key.decrypt(ct, OAEP)).rstrip(b"=").decode()})
                if self.path.endswith(":asymmetricDecrypt") and self.headers["Authorization"] == "Bearer gcp-at":
                    return self.reply({"plaintext": base64.b64encode(key.decrypt(base64.b64decode(body["ciphertext"]), OAEP)).decode()})
                self.send_response(403)
                self.end_headers()

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_address[1]}"

        az = cloud.Azure("https://v.vault.azure.net/keys/ssm/1", "api://ssm-vault")
        az.imds, az.key_url = base, base + "/keys/ssm/1"
        self.assertEqual(az.identity("vault.test"), "az-api://ssm-vault")  # the registered audience, not the server ID
        self.assertEqual(az.decrypt(blob), PLAIN)

        g = cloud.GCP("projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1")
        g.metadata, g.km = base, base
        self.assertEqual(g.identity("vault.test"), "gcp-vault.test-full")
        self.assertEqual(g.decrypt(blob), PLAIN)
        self.assertIn("/v1/projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1:asymmetricDecrypt", seen)

        for bad in (lambda: cloud.Azure("http://v/keys/k", "a"), lambda: cloud.Azure("https://v.vault.azure.net/keys/k/1", ""),
                    lambda: cloud.GCP("my-key"), lambda: cloud.AWS("not-an-arn")):
            with self.assertRaises(cloud.CloudError):
                bad()


@unittest.skipUnless(os.environ.get("SSM_TEST_FLOCI"), "set SSM_TEST_FLOCI=1 with floci running")
class AWSFloci(unittest.TestCase):
    def test_sign_and_decrypt(self):
        ep = "http://localhost:4566"
        env = {**os.environ, "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test", "AWS_DEFAULT_REGION": "us-east-1"}
        aws = lambda *a: subprocess.run(["aws", "--endpoint-url", ep, "--output", "text", *a], env=env, check=True, capture_output=True, text=True).stdout.strip()
        arn = aws("kms", "create-key", "--key-spec", "RSA_2048", "--key-usage", "ENCRYPT_DECRYPT", "--query", "KeyMetadata.Arn")
        pub = serialization.load_der_public_key(base64.b64decode(aws("kms", "get-public-key", "--key-id", arn, "--query", "PublicKey")))
        role = f"ssm-py-{time.time_ns()}"
        aws("iam", "create-role", "--role-name", role, "--assume-role-policy-document",
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}')
        k, s, t = aws("sts", "assume-role", "--role-arn", f"arn:aws:iam::000000000000:role/{role}", "--role-session-name", "ci",
                      "--query", "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]").split()
        old = {v: os.environ.get(v) for v in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL")}
        os.environ.update(AWS_ACCESS_KEY_ID=k, AWS_SECRET_ACCESS_KEY=s, AWS_SESSION_TOKEN=t, AWS_ENDPOINT_URL=ep)
        self.addCleanup(lambda: [os.environ.pop(v, None) if x is None else os.environ.__setitem__(v, x) for v, x in old.items()])
        a = cloud.AWS(arn, ep)
        proof = json.loads(base64.urlsafe_b64decode(a.identity("vault.test") + "=="))
        out = cloud._http("POST", ep + "/", proof["headers"], proof["body"].encode()).decode()
        self.assertIn(f"assumed-role/{role}/ci", out)
        self.assertIn("x-ssm-server-id", proof["headers"]["Authorization"])
        self.assertEqual(a.decrypt(pub.encrypt(PLAIN, OAEP)), PLAIN)


if __name__ == "__main__":
    unittest.main()
