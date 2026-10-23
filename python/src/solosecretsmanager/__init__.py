"""Read secrets from a SoloSecretsManager server inside CI jobs (SDK-01, SEC-MACH-02).

The server only returns ciphertext. The job proves who it is with a GitHub Actions OIDC token, gets the environment
key wrapped under SSM_CI_KEY, and decrypts in memory. Nothing is written to disk (SDK-06).

    from solosecretsmanager import Client
    password = Client.from_env().get("DATABASE_PASSWORD")

Pure port of the decrypt subset (SDK-02), checked against testvectors/machine-v1.json (QA-G-03).
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import ssl
import struct
import threading
import time
import urllib.parse
import urllib.request
import uuid
from typing import Callable, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = ["Client", "SSMError", "github_token", "gitlab_token"]


class SSMError(Exception):
    pass


def _b64d(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s.strip().rstrip("=") + "=" * (-len(s.strip().rstrip("=")) % 4))
    except Exception as e:
        raise SSMError("malformed base64") from e


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# | magic "SSM" | fmt_ver u8 | alg_id u8 | key_id 16B | nonce 12B | ciphertext … | tag 16B |
# AAD = fmt_ver ‖ alg_id ‖ key_id ‖ object_id ‖ object_revision (u64 big-endian)
_HEADER = 3 + 1 + 1 + 16 + 12


def _open(key_id: bytes, key: bytes, obj: bytes, revision: int, env: bytes) -> bytes:
    if len(env) < _HEADER + 16 or env[:3] != b"SSM":
        raise SSMError("malformed envelope")
    if env[3] != 1 or env[4] != 1:
        raise SSMError("unsupported envelope version or algorithm")
    if env[5:21] != key_id:
        raise SSMError("envelope sealed under a different key")
    aad = bytes([1, 1]) + key_id + obj + struct.pack(">Q", revision)
    try:
        return AESGCM(key).decrypt(env[21:33], env[_HEADER:], aad)
    except InvalidTag as e:
        raise SSMError("decryption failed (tampered, swapped or wrong key)") from e


def _unwrap(key_id: bytes, key: bytes, obj: bytes, env: bytes) -> tuple[bytes, bytes]:
    plain = _open(key_id, key, obj, 0, env)
    if len(plain) != 48:
        raise SSMError("malformed wrapped key")
    return plain[:16], plain[16:]


def _uuid(s: str) -> bytes:
    try:
        return uuid.UUID(s).bytes
    except (ValueError, AttributeError, TypeError) as e:
        raise SSMError("bad UUID") from e


def decrypt_exchange(ci_key: str, environment_id: str, exchange: dict) -> dict[str, str]:
    """Opens the environment key with the CI key, then each item (SEC-MACH-05). Any failure fails the whole call."""
    raw = _b64d(ci_key)
    if len(raw) != 48:
        raise SSMError("SSM_CI_KEY is missing or malformed")
    env = _uuid(environment_id)
    return decrypt_items(*_unwrap(raw[:16], raw[16:], env, _b64d(exchange["wrapped_key"])), exchange)


def cloud_env_key(plain: bytes, environment_id: str) -> tuple[bytes, bytes]:
    """What a cloud KMS decrypted: environment ID ‖ key ID ‖ key; it must be this environment's (SEC-MACH-06/08/09)."""
    if len(plain) != 64 or plain[:16] != _uuid(environment_id):
        raise SSMError("KMS returned a key for another environment")
    return plain[16:32], plain[32:]


def decrypt_items(ek_id: bytes, ek: bytes, exchange: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for it in exchange["items"]:
        iid = _uuid(it["id"])
        ik_id, ik = _unwrap(ek_id, ek, iid, _b64d(it["item_key"]))
        payload = json.loads(_open(ik_id, ik, iid, int(it["revision"]), _b64d(it["payload"])))
        name = payload.get("name", "")
        if name in out:
            raise SSMError(f"two secrets are named {name!r}; rename one in the app")
        out[name] = payload.get("secret", "")
    return out


def _spki_pin(cert_der: bytes) -> str:
    spki = x509.load_der_x509_certificate(cert_der).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return _b64e(hashlib.sha256(spki).digest())


def verify_attestation(a: dict, pin: str, server_id: str, conn_pin: str) -> set[str]:
    """SEC-TLS-05: the identity key matches pin, signed the statement for this server, and attests conn_pin."""
    try:
        der, body, sig = _b64d(a["identity_public_key"]), _b64d(a["statement"]), _b64d(a["signature"])
        key = serialization.load_der_public_key(der)
    except (KeyError, ValueError, SSMError) as e:
        raise SSMError("malformed attestation") from e
    if _b64e(hashlib.sha256(der).digest()) != pin or not isinstance(key, ec.EllipticCurvePublicKey):
        raise SSMError("server identity does not match the pin")
    try:
        key.verify(sig, body, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise SSMError("server identity does not match the pin") from e
    st = json.loads(body)
    if st.get("purpose") != "ssm-tls-attestation-v1" or st.get("server_id") != server_id:
        raise SSMError("attestation is not for this server")
    pins = set(st.get("tls_pins") or [])
    if conn_pin not in pins:
        raise SSMError("TLS certificate is not attested by the server identity")
    return pins


def gitlab_token(audience: str) -> str:
    """The job's ID token, declared with the server ID as audience: id_tokens: SSM_ID_TOKEN: aud: <server ID>."""
    t = os.environ.get("SSM_ID_TOKEN")
    if not t:
        raise SSMError("SSM_ID_TOKEN is not set; declare it under id_tokens with the server ID as aud")
    return t


def github_token(audience: str) -> str:
    """Asks the GitHub Actions runner for an OIDC token. The workflow needs `permissions: id-token: write`."""
    url, tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not tok:
        raise SSMError("not in GitHub Actions, or the workflow lacks `permissions: id-token: write`")
    req = urllib.request.Request(url + "&audience=" + urllib.parse.quote(audience), headers={"Authorization": "Bearer " + tok})
    with urllib.request.urlopen(req, timeout=30) as r:
        value = json.load(r).get("value")
    if not value:
        raise SSMError("GitHub did not issue an OIDC token")
    return value


class Client:
    """Caches one environment's secrets in memory for `ttl` seconds (SDK-04); a revoked grant stops at the next refresh.

    ponytail: Python strings can't be wiped; secrets stay in the heap until collected. SDK-06 only forbids disk.
    """

    def __init__(self, url: str, server_id: str, pin: str, environment_id: str, ci_key: str = "", ttl: float = 300,
                 credential: Optional[Callable[[str], str]] = None, kind: str = "github", cloud_backend=None):
        """kind is "github" or "gitlab" for the CI-key kinds; cloud_backend (cloud.AWS, cloud.Azure or cloud.GCP)
        replaces the CI key for cloud workloads (SEC-MACH-06/08/09)."""
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or not u.hostname:
            raise SSMError("URL must be https://host[:port]")
        if not server_id or not pin:
            raise SSMError("server ID and pin are required")
        _uuid(environment_id)
        if kind not in ("github", "gitlab"):
            raise SSMError("kind must be github or gitlab")
        if cloud_backend is None and len(_b64d(ci_key or "")) != 48:
            raise SSMError("SSM_CI_KEY is missing or malformed")
        self._kind, self._cloud = kind, cloud_backend
        self._host, self._port = u.hostname, u.port or 443
        self._server_id, self._pin, self._env, self._ci = server_id, pin, environment_id, ci_key
        self._ttl, self._credential = ttl, credential or (gitlab_token if kind == "gitlab" else github_token)
        self._pins: Optional[set[str]] = None
        self._secrets: Optional[dict[str, str]] = None
        self._fetched = 0.0
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls, **kw) -> "Client":
        """SSM_URL, SSM_SERVER_ID, SSM_PIN, SSM_ENVIRONMENT_ID and SSM_CI_KEY; for cloud workloads SSM_AWS_KMS_KEY,
        SSM_AZURE_KEY (+ SSM_AZURE_AUDIENCE) or SSM_GCP_KMS_KEY instead of SSM_CI_KEY (SDK-09)."""
        from . import cloud
        e = os.environ.get
        try:
            backend = cloud.from_env()
        except cloud.CloudError as err:
            raise SSMError(str(err)) from err
        kw.setdefault("kind", "gitlab" if e("GITLAB_CI") == "true" else "github")
        return cls(e("SSM_URL", ""), e("SSM_SERVER_ID", ""), e("SSM_PIN", ""), e("SSM_ENVIRONMENT_ID", ""), e("SSM_CI_KEY", ""),
                   cloud_backend=backend, **kw)

    def get(self, name: str) -> str:
        all_ = self.all()
        if name not in all_:
            raise SSMError(f"no secret named {name!r} in this environment")
        return all_[name]

    def all(self) -> dict[str, str]:
        with self._lock:
            if self._secrets is None or time.monotonic() - self._fetched >= self._ttl:
                self._refresh()
            return dict(self._secrets)

    def _request(self, method: str, path: str, body: Optional[bytes]) -> tuple[int, bytes, str]:
        """One request on a fresh TLS 1.3 connection; returns the certificate pin seen on it."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # replaced by the pin checks
        conn = http.client.HTTPSConnection(self._host, self._port, context=ctx, timeout=30)
        try:
            conn.connect()
            conn_pin = _spki_pin(conn.sock.getpeercert(binary_form=True))
            if self._pins is not None and conn_pin not in self._pins:
                raise SSMError("server certificate is not pinned")
            conn.request(method, path, body=body, headers={"Content-Type": "application/json"} if body else {})
            r = conn.getresponse()
            return r.status, r.read(64 << 20), conn_pin
        finally:
            conn.close()

    def _refresh(self) -> None:
        if self._pins is None:
            status, body, conn_pin = self._request("GET", "/v1/tls/attestation", None)
            if status != 200:
                raise SSMError("server has no valid TLS attestation")
            self._pins = verify_attestation(json.loads(body), self._pin, self._server_id, conn_pin)
        from . import cloud
        try:
            kind, cred = (self._cloud.kind, self._cloud.identity(self._server_id)) if self._cloud else (self._kind, self._credential(self._server_id))
        except cloud.CloudError as err:
            raise SSMError(str(err)) from err
        req = json.dumps({"environment_id": self._env, "kind": kind, "credential": cred}).encode()
        try:
            status, body, _ = self._request("POST", "/v1/machine/exchange", req)
        except (OSError, SSMError):
            self._pins = None  # the certificate may have rotated: attest again next time
            raise
        if status != 200:
            raise SSMError(f"server refused this machine identity ({status})")
        ex = json.loads(body)
        if self._cloud:
            try:
                plain = self._cloud.decrypt(_b64d(ex["wrapped_key"]))
            except cloud.CloudError as err:
                raise SSMError(str(err)) from err
            self._secrets = decrypt_items(*cloud_env_key(plain, self._env), ex)
        else:
            self._secrets = decrypt_exchange(self._ci, self._env, ex)
        self._fetched = time.monotonic()
