// Cloud workload identities without cloud SDKs (SEC-MACH-06/08/09, SDK-09): a small SigV4 signer checked against
// testvectors/aws-sigv4.json, the AWS credential chain, and the Azure and GCP metadata and KMS REST calls.

import crypto from "node:crypto";
import fs from "node:fs";

export class CloudError extends Error {}

export const STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15";

async function http(method, url, headers = {}, body) {
  let r;
  try {
    r = await fetch(url, { method, headers, body, signal: AbortSignal.timeout(15_000) });
  } catch (e) {
    throw new CloudError(`${method} ${url.split("?")[0]}: ${e.message}`);
  }
  const text = await r.text();
  if (!r.ok) throw new CloudError(`${method} ${url.split("?")[0]}: ${r.status} ${text.slice(0, 500).trim()}`);
  return text;
}

const sha256hex = (s) => crypto.createHash("sha256").update(s).digest("hex");
const hmac = (k, s) => crypto.createHmac("sha256", k).update(s).digest();

/**
 * Returns the headers to send: the given ones plus Host, Content-Length, X-Amz-Date, the session token and
 * Authorization. Same canonical form as AWS's Go signer (content-length is signed).
 */
export function sigv4(method, url, region, service, headers, body, creds, now = new Date()) {
  const amz = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const day = amz.slice(0, 8);
  const u = new URL(url);
  const h = { ...headers, Host: u.host, "Content-Length": String(Buffer.byteLength(body)), "X-Amz-Date": amz };
  if (creds.token) h["X-Amz-Security-Token"] = creds.token;
  const canon = Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), String(v).trim().split(/\s+/).join(" ")]));
  const names = Object.keys(canon).sort();
  const signed = names.join(";");
  const creq = [method, u.pathname || "/", u.search.slice(1), names.map((k) => `${k}:${canon[k]}\n`).join(""), signed, sha256hex(body)].join("\n");
  const scope = `${day}/${region}/${service}/aws4_request`;
  const sts = ["AWS4-HMAC-SHA256", amz, scope, sha256hex(creq)].join("\n");
  let k = Buffer.from("AWS4" + creds.secret);
  for (const part of [day, region, service, "aws4_request"]) k = hmac(k, part);
  h.Authorization = `AWS4-HMAC-SHA256 Credential=${creds.key}/${scope}, SignedHeaders=${signed}, Signature=${hmac(k, sts).toString("hex")}`;
  return h;
}

/** Environment, web identity (EKS IRSA), container (ECS, EKS Pod Identity), then EC2 IMDSv2 (SDK-09). */
export async function awsCredentials() {
  const e = process.env;
  if (e.AWS_ACCESS_KEY_ID && e.AWS_SECRET_ACCESS_KEY) return { key: e.AWS_ACCESS_KEY_ID, secret: e.AWS_SECRET_ACCESS_KEY, token: e.AWS_SESSION_TOKEN ?? "" };
  let c;
  if (e.AWS_WEB_IDENTITY_TOKEN_FILE && e.AWS_ROLE_ARN) {
    const q = new URLSearchParams({ Action: "AssumeRoleWithWebIdentity", Version: "2011-06-15", RoleArn: e.AWS_ROLE_ARN,
      RoleSessionName: e.AWS_ROLE_SESSION_NAME ?? "ssm-sdk", WebIdentityToken: fs.readFileSync(e.AWS_WEB_IDENTITY_TOKEN_FILE, "utf8").trim() });
    const sts = (e.AWS_ENDPOINT_URL_STS ?? e.AWS_ENDPOINT_URL ?? "https://sts.amazonaws.com").replace(/\/$/, "");
    const x = JSON.parse(await http("POST", sts + "/", { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, q.toString()));
    c = x.AssumeRoleWithWebIdentityResponse.AssumeRoleWithWebIdentityResult.Credentials;
    return { key: c.AccessKeyId, secret: c.SecretAccessKey, token: c.SessionToken };
  }
  if (e.AWS_CONTAINER_CREDENTIALS_FULL_URI || e.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) {
    const hdr = {};
    if (e.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE) hdr.Authorization = fs.readFileSync(e.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE, "utf8").trim();
    else if (e.AWS_CONTAINER_AUTHORIZATION_TOKEN) hdr.Authorization = e.AWS_CONTAINER_AUTHORIZATION_TOKEN;
    c = JSON.parse(await http("GET", e.AWS_CONTAINER_CREDENTIALS_FULL_URI ?? "http://169.254.170.2" + e.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, hdr));
  } else {
    const imds = "http://169.254.169.254";
    const t = await http("PUT", imds + "/latest/api/token", { "X-aws-ec2-metadata-token-ttl-seconds": "300" });
    const role = (await http("GET", imds + "/latest/meta-data/iam/security-credentials/", { "X-aws-ec2-metadata-token": t })).trim().split(/\s+/)[0];
    c = JSON.parse(await http("GET", imds + "/latest/meta-data/iam/security-credentials/" + role, { "X-aws-ec2-metadata-token": t }));
  }
  return { key: c.AccessKeyId, secret: c.SecretAccessKey, token: c.Token ?? "" };
}

export class AWS {
  kind = "aws";

  constructor(keyArn, stsEndpoint = "") {
    const p = String(keyArn).split(":");
    if (p.length < 6 || p[2] !== "kms" || !p[3]) throw new CloudError("SSM_AWS_KMS_KEY must be a KMS key ARN");
    [this.keyArn, this.region] = [keyArn, p[3]];
    this.sts = (stsEndpoint || "https://sts.amazonaws.com").replace(/\/$/, "");
    const e = process.env;
    this.kms = (e.AWS_ENDPOINT_URL_KMS ?? e.AWS_ENDPOINT_URL ?? `https://kms.${this.region}.amazonaws.com`).replace(/\/$/, "");
  }

  async identity(serverId) {
    const host = new URL(this.sts).hostname;
    const parts = host.split(".");
    const region = host.startsWith("sts.") && parts.length === 4 ? parts[1] : "us-east-1";
    const h = sigv4("POST", this.sts + "/", region, "sts",
      { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "X-Ssm-Server-Id": serverId }, STS_BODY, await awsCredentials());
    delete h.Host;
    delete h["Content-Length"];
    return Buffer.from(JSON.stringify({ method: "POST", url: this.sts + "/", headers: h, body: STS_BODY })).toString("base64url");
  }

  async decrypt(blob) {
    const body = JSON.stringify({ KeyId: this.keyArn, CiphertextBlob: Buffer.from(blob).toString("base64"), EncryptionAlgorithm: "RSAES_OAEP_SHA_256" });
    const h = sigv4("POST", this.kms + "/", this.region, "kms",
      { "Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "TrentService.Decrypt" }, body, await awsCredentials());
    delete h.Host;
    delete h["Content-Length"]; // fetch sets them; the values are the same
    try {
      return Buffer.from(JSON.parse(await http("POST", this.kms + "/", h, body)).Plaintext, "base64");
    } catch (e) {
      throw new CloudError("KMS refused to decrypt the environment key: " + e.message);
    }
  }
}

export class Azure {
  kind = "azure";

  constructor(keyUrl, audience) {
    let u;
    try { u = new URL(keyUrl); } catch { u = null; }
    if (!u || u.protocol !== "https:" || !u.pathname.includes("/keys/")) {
      throw new CloudError("SSM_AZURE_KEY must be a Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>/<version>)");
    }
    if (!audience) throw new CloudError("SSM_AZURE_AUDIENCE is required (the application ID URI registered for the server)");
    [this.keyUrl, this.audience, this.imds] = [keyUrl.replace(/\/$/, ""), audience, "http://169.254.169.254"];
  }

  async token(resource) {
    const e = process.env;
    const x = e.IDENTITY_ENDPOINT && e.IDENTITY_HEADER // App Service, Functions
      ? await http("GET", `${e.IDENTITY_ENDPOINT}?api-version=2019-08-01&resource=${encodeURIComponent(resource)}`, { "X-IDENTITY-HEADER": e.IDENTITY_HEADER })
      : await http("GET", `${this.imds}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=${encodeURIComponent(resource)}`, { Metadata: "true" });
    const tok = JSON.parse(x).access_token;
    if (!tok) throw new CloudError("Azure managed identity returned no token");
    return tok;
  }

  identity() {
    return this.token(this.audience);
  }

  async decrypt(blob) {
    const body = JSON.stringify({ alg: "RSA-OAEP-256", value: Buffer.from(blob).toString("base64url") });
    try {
      const v = JSON.parse(await http("POST", `${this.keyUrl}/decrypt?api-version=7.4`,
        { Authorization: "Bearer " + (await this.token("https://vault.azure.net")), "Content-Type": "application/json" }, body)).value;
      return Buffer.from(v, "base64url");
    } catch (e) {
      throw new CloudError("Key Vault refused to decrypt the environment key: " + e.message);
    }
  }
}

const SA = "/computeMetadata/v1/instance/service-accounts/default/";

export class GCP {
  kind = "gcp";

  constructor(keyVersion) {
    if (!String(keyVersion).startsWith("projects/") || !keyVersion.includes("/cryptoKeyVersions/")) {
      throw new CloudError("SSM_GCP_KMS_KEY must be a key version name (projects/…/cryptoKeys/…/cryptoKeyVersions/N)");
    }
    [this.keyVersion, this.metadata, this.km] = [keyVersion, "http://metadata.google.internal", "https://cloudkms.googleapis.com"];
  }

  async identity(serverId) {
    return (await http("GET", `${this.metadata}${SA}identity?format=full&audience=${encodeURIComponent(serverId)}`, { "Metadata-Flavor": "Google" })).trim();
  }

  async decrypt(blob) {
    const at = JSON.parse(await http("GET", this.metadata + SA + "token", { "Metadata-Flavor": "Google" })).access_token;
    try {
      const x = await http("POST", `${this.km}/v1/${this.keyVersion}:asymmetricDecrypt`, { Authorization: "Bearer " + at, "Content-Type": "application/json" },
        JSON.stringify({ ciphertext: Buffer.from(blob).toString("base64") }));
      return Buffer.from(JSON.parse(x).plaintext, "base64");
    } catch (e) {
      throw new CloudError("Cloud KMS refused to decrypt the environment key: " + e.message);
    }
  }
}

export function cloudFromEnv() {
  const e = process.env;
  if (e.SSM_AWS_KMS_KEY) return new AWS(e.SSM_AWS_KMS_KEY, e.SSM_AWS_STS_ENDPOINT ?? "");
  if (e.SSM_AZURE_KEY) return new Azure(e.SSM_AZURE_KEY, e.SSM_AZURE_AUDIENCE ?? "");
  if (e.SSM_GCP_KMS_KEY) return new GCP(e.SSM_GCP_KMS_KEY);
  return null;
}
