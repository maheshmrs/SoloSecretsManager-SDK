"""Cloud workload identities without cloud SDKs (SEC-MACH-06/08/09, SDK-09): a small SigV4 signer checked against
testvectors/aws-sigv4.json, the AWS credential chain, and the Azure and GCP metadata and KMS REST calls."""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import urllib.parse
import urllib.request
from typing import Optional

STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"


class CloudError(Exception):
    pass


def _http(method: str, url: str, headers: Optional[dict] = None, body: Optional[bytes] = None, timeout: float = 15) -> bytes:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(1 << 20)
    except urllib.error.HTTPError as e:
        raise CloudError(f"{method} {url.split('?')[0]}: {e.code} {e.read(500).decode(errors='replace').strip()}") from e
    except OSError as e:
        raise CloudError(f"{method} {url.split('?')[0]}: {e}") from e


# ---------- AWS (SEC-MACH-06) ----------

def sigv4(method: str, url: str, region: str, service: str, headers: dict, body: str, creds: dict,
          now: Optional[datetime.datetime] = None) -> dict:
    """Returns the headers to send: the given ones plus Host, Content-Length, X-Amz-Date, the session token and
    Authorization. Same canonical form as AWS's Go signer (content-length is signed)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    u = urllib.parse.urlsplit(url)
    h = {**headers, "Host": u.netloc, "Content-Length": str(len(body.encode())), "X-Amz-Date": amz}
    if creds.get("token"):
        h["X-Amz-Security-Token"] = creds["token"]
    canon = {k.lower(): " ".join(str(v).split()) for k, v in h.items()}
    signed = ";".join(sorted(canon))
    creq = "\n".join([method, u.path or "/", u.query, "".join(f"{k}:{canon[k]}\n" for k in sorted(canon)), signed,
                      hashlib.sha256(body.encode()).hexdigest()])
    scope = f"{day}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = ("AWS4" + creds["secret"]).encode()
    for part in (day, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    h["Authorization"] = f"AWS4-HMAC-SHA256 Credential={creds['key']}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return h


def aws_credentials() -> dict:
    """Environment, web identity (EKS IRSA), container (ECS, EKS Pod Identity), then EC2 IMDSv2 (SDK-09)."""
    e = os.environ.get
    if e("AWS_ACCESS_KEY_ID") and e("AWS_SECRET_ACCESS_KEY"):
        return {"key": e("AWS_ACCESS_KEY_ID"), "secret": e("AWS_SECRET_ACCESS_KEY"), "token": e("AWS_SESSION_TOKEN", "")}
    if e("AWS_WEB_IDENTITY_TOKEN_FILE") and e("AWS_ROLE_ARN"):
        tok = open(e("AWS_WEB_IDENTITY_TOKEN_FILE")).read().strip()
        q = urllib.parse.urlencode({"Action": "AssumeRoleWithWebIdentity", "Version": "2011-06-15", "RoleArn": e("AWS_ROLE_ARN"),
                                    "RoleSessionName": e("AWS_ROLE_SESSION_NAME", "ssm-sdk"), "WebIdentityToken": tok})
        sts = e("AWS_ENDPOINT_URL_STS") or e("AWS_ENDPOINT_URL") or "https://sts.amazonaws.com"
        x = _http("POST", sts.rstrip("/") + "/", {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                  q.encode()).decode()
        c = json.loads(x)["AssumeRoleWithWebIdentityResponse"]["AssumeRoleWithWebIdentityResult"]["Credentials"]
        return {"key": c["AccessKeyId"], "secret": c["SecretAccessKey"], "token": c["SessionToken"]}
    full, rel = e("AWS_CONTAINER_CREDENTIALS_FULL_URI"), e("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    if full or rel:
        hdr = {}
        if e("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"):
            hdr["Authorization"] = open(e("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")).read().strip()
        elif e("AWS_CONTAINER_AUTHORIZATION_TOKEN"):
            hdr["Authorization"] = e("AWS_CONTAINER_AUTHORIZATION_TOKEN")
        c = json.loads(_http("GET", full or "http://169.254.170.2" + rel, hdr))
    else:
        imds = "http://169.254.169.254"
        t = _http("PUT", imds + "/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "300"}).decode()
        role = _http("GET", imds + "/latest/meta-data/iam/security-credentials/", {"X-aws-ec2-metadata-token": t}).decode().split()[0]
        c = json.loads(_http("GET", imds + "/latest/meta-data/iam/security-credentials/" + role, {"X-aws-ec2-metadata-token": t}))
    return {"key": c["AccessKeyId"], "secret": c["SecretAccessKey"], "token": c.get("Token", "")}


class AWS:
    kind = "aws"

    def __init__(self, key_arn: str, sts_endpoint: str = ""):
        p = key_arn.split(":")
        if len(p) < 6 or p[2] != "kms" or not p[3]:
            raise CloudError("SSM_AWS_KMS_KEY must be a KMS key ARN")
        self.key_arn, self.region = key_arn, p[3]
        self.sts = (sts_endpoint or "https://sts.amazonaws.com").rstrip("/")
        self.kms = (os.environ.get("AWS_ENDPOINT_URL_KMS") or os.environ.get("AWS_ENDPOINT_URL") or f"https://kms.{self.region}.amazonaws.com").rstrip("/")

    def identity(self, server_id: str) -> str:
        host = urllib.parse.urlsplit(self.sts).hostname or ""
        region = host.split(".")[1] if host.startswith("sts.") and host.count(".") == 3 else "us-east-1"
        h = sigv4("POST", self.sts + "/", region, "sts",
                  {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "X-Ssm-Server-Id": server_id}, STS_BODY, aws_credentials())
        h.pop("Host"), h.pop("Content-Length")
        proof = json.dumps({"method": "POST", "url": self.sts + "/", "headers": h, "body": STS_BODY}).encode()
        return base64.urlsafe_b64encode(proof).rstrip(b"=").decode()

    def decrypt(self, blob: bytes) -> bytes:
        body = json.dumps({"KeyId": self.key_arn, "CiphertextBlob": base64.b64encode(blob).decode(), "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"})
        h = sigv4("POST", self.kms + "/", self.region, "kms", {"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "TrentService.Decrypt"},
                  body, aws_credentials())
        h.pop("Host")
        try:
            return base64.b64decode(json.loads(_http("POST", self.kms + "/", h, body.encode()))["Plaintext"])
        except CloudError as e:
            raise CloudError("KMS refused to decrypt the environment key: " + str(e)) from e


# ---------- Azure (SEC-MACH-08) ----------

class Azure:
    kind = "azure"

    def __init__(self, key_url: str, audience: str):
        u = urllib.parse.urlsplit(key_url)
        if u.scheme != "https" or "/keys/" not in u.path:
            raise CloudError("SSM_AZURE_KEY must be a Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>/<version>)")
        if not audience:
            raise CloudError("SSM_AZURE_AUDIENCE is required (the application ID URI registered for the server)")
        self.key_url, self.audience, self.imds = key_url.rstrip("/"), audience, "http://169.254.169.254"

    def token(self, resource: str) -> str:
        e = os.environ.get
        if e("IDENTITY_ENDPOINT") and e("IDENTITY_HEADER"):  # App Service, Functions
            x = _http("GET", e("IDENTITY_ENDPOINT") + "?api-version=2019-08-01&resource=" + urllib.parse.quote(resource),
                      {"X-IDENTITY-HEADER": e("IDENTITY_HEADER")})
        else:
            x = _http("GET", self.imds + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" + urllib.parse.quote(resource),
                      {"Metadata": "true"})
        tok = json.loads(x).get("access_token")
        if not tok:
            raise CloudError("Azure managed identity returned no token")
        return tok

    def identity(self, server_id: str) -> str:
        return self.token(self.audience)

    def decrypt(self, blob: bytes) -> bytes:
        body = json.dumps({"alg": "RSA-OAEP-256", "value": base64.urlsafe_b64encode(blob).rstrip(b"=").decode()}).encode()
        try:
            v = json.loads(_http("POST", self.key_url + "/decrypt?api-version=7.4",
                                 {"Authorization": "Bearer " + self.token("https://vault.azure.net"), "Content-Type": "application/json"}, body))["value"]
        except CloudError as e:
            raise CloudError("Key Vault refused to decrypt the environment key: " + str(e)) from e
        return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))


# ---------- GCP (SEC-MACH-09) ----------

_SA = "/computeMetadata/v1/instance/service-accounts/default/"


class GCP:
    kind = "gcp"

    def __init__(self, key_version: str):
        if not key_version.startswith("projects/") or "/cryptoKeyVersions/" not in key_version:
            raise CloudError("SSM_GCP_KMS_KEY must be a key version name (projects/…/cryptoKeys/…/cryptoKeyVersions/N)")
        self.key_version, self.metadata, self.km = key_version, "http://metadata.google.internal", "https://cloudkms.googleapis.com"

    def identity(self, server_id: str) -> str:
        return _http("GET", self.metadata + _SA + "identity?format=full&audience=" + urllib.parse.quote(server_id),
                     {"Metadata-Flavor": "Google"}).decode().strip()

    def decrypt(self, blob: bytes) -> bytes:
        at = json.loads(_http("GET", self.metadata + _SA + "token", {"Metadata-Flavor": "Google"}))["access_token"]
        body = json.dumps({"ciphertext": base64.b64encode(blob).decode()}).encode()
        try:
            x = _http("POST", f"{self.km}/v1/{self.key_version}:asymmetricDecrypt",
                      {"Authorization": "Bearer " + at, "Content-Type": "application/json"}, body)
        except CloudError as e:
            raise CloudError("Cloud KMS refused to decrypt the environment key: " + str(e)) from e
        return base64.b64decode(json.loads(x)["plaintext"])


def from_env() -> Optional[object]:
    e = os.environ.get
    if e("SSM_AWS_KMS_KEY"):
        return AWS(e("SSM_AWS_KMS_KEY"), e("SSM_AWS_STS_ENDPOINT", ""))
    if e("SSM_AZURE_KEY"):
        return Azure(e("SSM_AZURE_KEY"), e("SSM_AZURE_AUDIENCE", ""))
    if e("SSM_GCP_KMS_KEY"):
        return GCP(e("SSM_GCP_KMS_KEY"))
    return None
