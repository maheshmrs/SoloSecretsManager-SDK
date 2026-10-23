// Read secrets from a SoloSecretsManager server inside CI jobs (SDK-01, SEC-MACH-02).
//
// The server only returns ciphertext. The job proves who it is with a GitHub Actions OIDC token, gets the
// environment key wrapped under SSM_CI_KEY, and decrypts in memory. Nothing is written to disk (SDK-06).
//
//   import { Client } from "@solosecretsmanager/sdk";
//   const pw = await Client.fromEnv().get("DATABASE_PASSWORD");
//
// Pure port of the decrypt subset with Node's crypto (SDK-02), checked against testvectors/machine-v1.json.

import crypto from "node:crypto";
import http from "node:http";
import tls from "node:tls";
import { CloudError, cloudFromEnv } from "./cloud.js";

export { AWS, Azure, GCP, CloudError, sigv4 } from "./cloud.js";

export class SSMError extends Error {}

const b64d = (s) => Buffer.from(String(s).replace(/=+$/, ""), "base64url");
const b64e = (b) => Buffer.from(b).toString("base64url");
const HEADER = 3 + 1 + 1 + 16 + 12;

// | magic "SSM" | fmt_ver u8 | alg_id u8 | key_id 16B | nonce 12B | ciphertext … | tag 16B |
// AAD = fmt_ver ‖ alg_id ‖ key_id ‖ object_id ‖ object_revision (u64 big-endian)
function open(keyId, key, obj, revision, env) {
  if (env.length < HEADER + 16 || env.subarray(0, 3).toString("latin1") !== "SSM") throw new SSMError("malformed envelope");
  if (env[3] !== 1 || env[4] !== 1) throw new SSMError("unsupported envelope version or algorithm");
  if (!env.subarray(5, 21).equals(keyId)) throw new SSMError("envelope sealed under a different key");
  const rev = Buffer.alloc(8);
  rev.writeBigUInt64BE(BigInt(revision));
  const aad = Buffer.concat([Buffer.from([1, 1]), keyId, obj, rev]);
  try {
    const d = crypto.createDecipheriv("aes-256-gcm", key, env.subarray(21, 33));
    d.setAAD(aad);
    d.setAuthTag(env.subarray(env.length - 16));
    return Buffer.concat([d.update(env.subarray(HEADER, env.length - 16)), d.final()]);
  } catch {
    throw new SSMError("decryption failed (tampered, swapped or wrong key)");
  }
}

function unwrap(keyId, key, obj, env) {
  const p = open(keyId, key, obj, 0, env);
  if (p.length !== 48) throw new SSMError("malformed wrapped key");
  return [p.subarray(0, 16), p.subarray(16)];
}

function uuidBytes(s) {
  const h = String(s).replaceAll("-", "");
  if (!/^[0-9a-fA-F]{32}$/.test(h)) throw new SSMError("bad UUID");
  return Buffer.from(h, "hex");
}

/** Opens the environment key with the CI key, then each item (SEC-MACH-05). Any failure fails the whole call. */
export function decryptExchange(ciKey, environmentId, exchange) {
  const raw = b64d(ciKey ?? "");
  if (raw.length !== 48) throw new SSMError("SSM_CI_KEY is missing or malformed");
  const [ekId, ek] = unwrap(raw.subarray(0, 16), raw.subarray(16), uuidBytes(environmentId), b64d(exchange.wrapped_key));
  return decryptItems(ekId, ek, exchange);
}

/** What a cloud KMS decrypted: environment ID ‖ key ID ‖ key; it must be this environment's (SEC-MACH-06/08/09). */
export function cloudEnvKey(plain, environmentId) {
  if (plain.length !== 64 || !plain.subarray(0, 16).equals(uuidBytes(environmentId))) throw new SSMError("KMS returned a key for another environment");
  return [plain.subarray(16, 32), plain.subarray(32)];
}

export function decryptItems(ekId, ek, exchange) {
  const out = {};
  for (const it of exchange.items) {
    const id = uuidBytes(it.id);
    const [ikId, ik] = unwrap(ekId, ek, id, b64d(it.item_key));
    const p = JSON.parse(open(ikId, ik, id, it.revision, b64d(it.payload)).toString("utf8"));
    const name = p.name ?? "";
    if (Object.hasOwn(out, name)) throw new SSMError(`two secrets are named "${name}"; rename one in the app`);
    out[name] = p.secret ?? "";
  }
  return out;
}

function spkiPin(certDer) {
  const spki = new crypto.X509Certificate(certDer).publicKey.export({ type: "spki", format: "der" });
  return b64e(crypto.createHash("sha256").update(spki).digest());
}

/** SEC-TLS-05: the identity key matches pin, signed the statement for this server, and attests connPin. */
export function verifyAttestation(a, pin, serverId, connPin) {
  let der, body, sig, key;
  try {
    [der, body, sig] = [b64d(a.identity_public_key), b64d(a.statement), b64d(a.signature)];
    key = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    throw new SSMError("malformed attestation");
  }
  const hash = b64e(crypto.createHash("sha256").update(der).digest());
  if (hash !== pin || key.asymmetricKeyType !== "ec" || !crypto.verify("sha256", body, { key, dsaEncoding: "der" }, sig)) {
    throw new SSMError("server identity does not match the pin");
  }
  const st = JSON.parse(body.toString("utf8"));
  if (st.purpose !== "ssm-tls-attestation-v1" || st.server_id !== serverId) throw new SSMError("attestation is not for this server");
  const pins = new Set(st.tls_pins ?? []);
  if (!pins.has(connPin)) throw new SSMError("TLS certificate is not attested by the server identity");
  return pins;
}

/** The job's ID token, declared with the server ID as audience: id_tokens: SSM_ID_TOKEN: aud: <server ID>. */
export async function gitlabToken() {
  if (!process.env.SSM_ID_TOKEN) throw new SSMError("SSM_ID_TOKEN is not set; declare it under id_tokens with the server ID as aud");
  return process.env.SSM_ID_TOKEN;
}

/** Asks the GitHub Actions runner for an OIDC token. The workflow needs `permissions: id-token: write`. */
export async function githubToken(audience) {
  const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL, tok = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !tok) throw new SSMError("not in GitHub Actions, or the workflow lacks `permissions: id-token: write`");
  const r = await fetch(`${url}&audience=${encodeURIComponent(audience)}`, { headers: { Authorization: `Bearer ${tok}` } });
  const v = r.ok ? (await r.json()).value : null;
  if (!v) throw new SSMError("GitHub did not issue an OIDC token");
  return v;
}

/**
 * Caches one environment's secrets in memory for `ttlMs` (SDK-04); a revoked grant stops at the next refresh.
 * ponytail: JS strings can't be wiped; secrets stay in the heap until collected. SDK-06 only forbids disk.
 */
export class Client {
  #host; #port; #serverId; #pin; #env; #ciKey; #ttl; #credential; #kind; #cloud; #pins = null; #secrets = null; #fetched = 0; #pending = null;

  /**
   * kind is "github" or "gitlab" for the CI-key kinds; cloud (an AWS, Azure or GCP backend from this package) replaces
   * the CI key for cloud workloads (SEC-MACH-06/08/09).
   */
  constructor({ url, serverId, pin, environmentId, ciKey, ttlMs = 300_000, credential, kind = "github", cloud = null }) {
    let u;
    try { u = new URL(url); } catch { u = null; }
    if (!u || u.protocol !== "https:" || !u.hostname) throw new SSMError("URL must be https://host[:port]");
    if (!serverId || !pin) throw new SSMError("server ID and pin are required");
    uuidBytes(environmentId);
    if (kind !== "github" && kind !== "gitlab") throw new SSMError("kind must be github or gitlab");
    if (!cloud && b64d(ciKey ?? "").length !== 48) throw new SSMError("SSM_CI_KEY is missing or malformed");
    [this.#kind, this.#cloud] = [kind, cloud];
    credential ??= kind === "gitlab" ? gitlabToken : githubToken;
    this.#host = u.hostname.replace(/^\[|\]$/g, "");
    this.#port = Number(u.port || 443);
    [this.#serverId, this.#pin, this.#env, this.#ciKey, this.#ttl, this.#credential] = [serverId, pin, environmentId, ciKey, ttlMs, credential];
  }

  /** SSM_URL, SSM_SERVER_ID, SSM_PIN, SSM_ENVIRONMENT_ID and SSM_CI_KEY; for cloud workloads SSM_AWS_KMS_KEY,
   *  SSM_AZURE_KEY (+ SSM_AZURE_AUDIENCE) or SSM_GCP_KMS_KEY instead of SSM_CI_KEY (SDK-09). */
  static fromEnv(opts = {}) {
    const e = process.env;
    let cloud;
    try { cloud = cloudFromEnv(); } catch (err) { throw new SSMError(err.message); }
    return new Client({ url: e.SSM_URL, serverId: e.SSM_SERVER_ID, pin: e.SSM_PIN, environmentId: e.SSM_ENVIRONMENT_ID, ciKey: e.SSM_CI_KEY,
      kind: e.GITLAB_CI === "true" ? "gitlab" : "github", cloud, ...opts });
  }

  async get(name) {
    const all = await this.all();
    if (!Object.hasOwn(all, name)) throw new SSMError(`no secret named "${name}" in this environment`);
    return all[name];
  }

  async all() {
    if (this.#secrets === null || Date.now() - this.#fetched >= this.#ttl) {
      this.#pending ??= this.#refresh().finally(() => { this.#pending = null; });
      await this.#pending;
    }
    return { ...this.#secrets };
  }

  /** One request on a fresh TLS 1.3 connection, sent only after the certificate's pin is checked. */
  #request(method, path, body) {
    return new Promise((resolve, reject) => {
      let connPin;
      const req = http.request({
        method, path, host: this.#host, port: this.#port,
        headers: body ? { "Content-Type": "application/json", "Content-Length": body.length } : {},
        createConnection: (_opts, cb) => {
          const s = tls.connect({ host: this.#host, port: this.#port, servername: /^[\d.:]+$/.test(this.#host) ? undefined : this.#host,
            rejectUnauthorized: false, minVersion: "TLSv1.3" }, () => { // replaced by the pin checks
            connPin = spkiPin(s.getPeerCertificate(true).raw);
            if (this.#pins !== null && !this.#pins.has(connPin)) {
              s.destroy();
              return cb(new SSMError("server certificate is not pinned"));
            }
            cb(null, s);
          });
          s.once("error", cb);
        },
      }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks), connPin }));
        res.on("error", reject);
      });
      req.setTimeout(30_000, () => req.destroy(new SSMError("request timed out")));
      req.on("error", reject);
      req.end(body);
    });
  }

  async #refresh() {
    if (this.#pins === null) {
      const r = await this.#request("GET", "/v1/tls/attestation");
      if (r.status !== 200) throw new SSMError("server has no valid TLS attestation");
      this.#pins = verifyAttestation(JSON.parse(r.body.toString("utf8")), this.#pin, this.#serverId, r.connPin);
    }
    let kind = this.#kind, credential;
    try {
      if (this.#cloud) [kind, credential] = [this.#cloud.kind, await this.#cloud.identity(this.#serverId)];
      else credential = await this.#credential(this.#serverId);
    } catch (e) {
      throw e instanceof CloudError ? new SSMError(e.message) : e;
    }
    const body = Buffer.from(JSON.stringify({ environment_id: this.#env, kind, credential }));
    let r;
    try {
      r = await this.#request("POST", "/v1/machine/exchange", body);
    } catch (e) {
      this.#pins = null; // the certificate may have rotated: attest again next time
      throw e;
    }
    if (r.status !== 200) throw new SSMError(`server refused this machine identity (${r.status})`);
    const ex = JSON.parse(r.body.toString("utf8"));
    if (this.#cloud) {
      let plain;
      try { plain = await this.#cloud.decrypt(b64d(ex.wrapped_key)); } catch (e) { throw e instanceof CloudError ? new SSMError(e.message) : e; }
      this.#secrets = decryptItems(...cloudEnvKey(plain, this.#env), ex);
    } else {
      this.#secrets = decryptExchange(this.#ciKey, this.#env, ex);
    }
    this.#fetched = Date.now();
  }
}
