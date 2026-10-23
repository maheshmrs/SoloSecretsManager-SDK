// SDK-09: SigV4 matches AWS's Go signer; Azure/GCP REST calls; AWS against floci (SSM_TEST_FLOCI=1).
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { AWS, Azure, GCP, CloudError, sigv4 } from "../cloud.js";
import { cloudEnvKey, SSMError } from "../index.js";

const SIG = JSON.parse(fs.readFileSync(new URL("../../testvectors/aws-sigv4.json", import.meta.url)));
const PLAIN = Buffer.from("environment-id-key-id-and-key-bytes-sixty-four-bytes-long......");
const oaep = { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" };

test("sigv4 vectors", () => {
  const creds = { key: SIG.access_key_id, secret: SIG.secret_access_key, token: SIG.session_token };
  for (const c of SIG.cases) {
    const h = sigv4(c.method, c.url, c.region, c.service, c.headers, c.body, creds, new Date(SIG.time));
    for (const [k, v] of Object.entries(c.signed)) assert.equal(h[k], v, `${c.name}: ${k}`);
  }
});

test("cloud env key", () => {
  const env = "e0e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0";
  const good = Buffer.concat([Buffer.from(env.replaceAll("-", ""), "hex"), Buffer.from([...Array(48).keys()])]);
  assert.deepEqual(cloudEnvKey(good, env)[0], Buffer.from([...Array(16).keys()]));
  assert.throws(() => cloudEnvKey(good, "e1e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0"), SSMError);
});

test("azure and gcp", async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const blob = crypto.publicEncrypt({ key: publicKey, ...oaep }, PLAIN);
  const dec = (ct) => crypto.privateDecrypt({ key: privateKey, ...oaep }, ct);
  const seen = [];
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    seen.push(req.method + " " + req.url);
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      const json = (o) => res.end(JSON.stringify(o));
      if (u.pathname === "/metadata/identity/oauth2/token" && req.headers.metadata === "true") return json({ access_token: "az-" + u.searchParams.get("resource") });
      if (u.pathname.endsWith("/identity") && req.headers["metadata-flavor"] === "Google") return res.end(`gcp-${u.searchParams.get("audience")}-${u.searchParams.get("format")}`);
      if (u.pathname.endsWith("/token") && req.headers["metadata-flavor"] === "Google") return json({ access_token: "gcp-at" });
      const b = data ? JSON.parse(data) : {};
      if (u.pathname.endsWith("/decrypt") && req.headers.authorization === "Bearer az-https://vault.azure.net" && b.alg === "RSA-OAEP-256") {
        return json({ value: dec(Buffer.from(b.value, "base64url")).toString("base64url") });
      }
      if (u.pathname.endsWith(":asymmetricDecrypt") && req.headers.authorization === "Bearer gcp-at") return json({ plaintext: dec(Buffer.from(b.ciphertext, "base64")).toString("base64") });
      res.statusCode = 403;
      res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const az = new Azure("https://v.vault.azure.net/keys/ssm/1", "api://ssm-vault");
    [az.imds, az.keyUrl] = [base, base + "/keys/ssm/1"];
    assert.equal(await az.identity("vault.test"), "az-api://ssm-vault"); // the registered audience, not the server ID
    assert.deepEqual(await az.decrypt(blob), PLAIN);
    const g = new GCP("projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1");
    [g.metadata, g.km] = [base, base];
    assert.equal(await g.identity("vault.test"), "gcp-vault.test-full");
    assert.deepEqual(await g.decrypt(blob), PLAIN);
    assert.ok(seen.some((s) => s.includes("/v1/projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1:asymmetricDecrypt")));
  } finally {
    srv.close();
  }
  for (const bad of [() => new Azure("http://v/keys/k", "a"), () => new Azure("https://v.vault.azure.net/keys/k/1", ""), () => new GCP("k"), () => new AWS("x")]) {
    assert.throws(bad, CloudError);
  }
});

test("aws against floci", { skip: !process.env.SSM_TEST_FLOCI && "set SSM_TEST_FLOCI=1 with floci running" }, async () => {
  const ep = "http://localhost:4566";
  const env = { ...process.env, AWS_ACCESS_KEY_ID: "test", AWS_SECRET_ACCESS_KEY: "test", AWS_DEFAULT_REGION: "us-east-1" };
  const aws = (...a) => execFileSync("aws", ["--endpoint-url", ep, "--output", "text", ...a], { env }).toString().trim();
  const arn = aws("kms", "create-key", "--key-spec", "RSA_2048", "--key-usage", "ENCRYPT_DECRYPT", "--query", "KeyMetadata.Arn");
  const pub = crypto.createPublicKey({ key: Buffer.from(aws("kms", "get-public-key", "--key-id", arn, "--query", "PublicKey"), "base64"), format: "der", type: "spki" });
  const role = `ssm-node-${Date.now()}`;
  aws("iam", "create-role", "--role-name", role, "--assume-role-policy-document",
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');
  const [k, s, t] = aws("sts", "assume-role", "--role-arn", `arn:aws:iam::000000000000:role/${role}`, "--role-session-name", "ci",
    "--query", "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]").split(/\s+/);
  Object.assign(process.env, { AWS_ACCESS_KEY_ID: k, AWS_SECRET_ACCESS_KEY: s, AWS_SESSION_TOKEN: t, AWS_ENDPOINT_URL: ep });
  const a = new AWS(arn, ep);
  const proof = JSON.parse(Buffer.from(await a.identity("vault.test"), "base64url"));
  assert.ok(proof.headers.Authorization.includes("x-ssm-server-id"));
  const r = await fetch(ep + "/", { method: "POST", headers: proof.headers, body: proof.body });
  assert.ok((await r.text()).includes(`assumed-role/${role}/ci`));
  assert.deepEqual(await a.decrypt(crypto.publicEncrypt({ key: pub, ...oaep }, PLAIN)), PLAIN);
});
