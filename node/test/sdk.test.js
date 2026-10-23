// QA-G-03 contract plus an end-to-end run against a fake TLS server. Run: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import https from "node:https";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client, SSMError, decryptExchange, verifyAttestation } from "../index.js";

const V = JSON.parse(fs.readFileSync(new URL("../../testvectors/machine-v1.json", import.meta.url)));
const b64e = (b) => Buffer.from(b).toString("base64url");

test("contract: accept", () => assert.deepEqual(decryptExchange(V.ci_key, V.environment_id, V.exchange), V.expected));

test("contract: reject", () => {
  assert.ok(V.reject.length >= 10);
  for (const r of V.reject) assert.throws(() => decryptExchange(r.ci_key, r.environment_id, r.exchange), SSMError, r.name);
});

test("contract: attestation", () => {
  const a = V.attestation;
  assert.deepEqual([...verifyAttestation(a.attestation, a.pin, a.server_id, a.conn_pin)].sort(), [...a.pins].sort());
  for (const r of V.attestation_reject) assert.throws(() => verifyAttestation(r.attestation, r.pin, r.server_id, r.conn_pin), SSMError, r.name);
});

async function fakeServer(serverId, attestOwnCert = true) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ssm-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=localhost",
    "-days", "1", "-keyout", `${dir}/k.pem`, "-out", `${dir}/c.pem`], { stdio: "ignore" });
  const cert = fs.readFileSync(`${dir}/c.pem`), key = fs.readFileSync(`${dir}/k.pem`);
  fs.rmSync(dir, { recursive: true });
  const spki = new crypto.X509Certificate(cert).publicKey.export({ type: "spki", format: "der" });
  const certPin = attestOwnCert ? b64e(crypto.createHash("sha256").update(spki).digest()) : "someone-else";
  const id = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = id.publicKey.export({ type: "spki", format: "der" });
  const body = Buffer.from(JSON.stringify({ purpose: "ssm-tls-attestation-v1", server_id: serverId, tls_pins: [certPin] }));
  const attestation = JSON.stringify({ identity_public_key: b64e(der), statement: b64e(body),
    signature: b64e(crypto.sign("sha256", body, { key: id.privateKey, dsaEncoding: "der" })) });
  const s = { calls: 0, pin: b64e(crypto.createHash("sha256").update(der).digest()) };
  s.server = https.createServer({ cert, key, minVersion: "TLSv1.3" }, (req, res) => {
    if (req.method === "GET" && req.url === "/v1/tls/attestation") return res.end(attestation);
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      s.calls++;
      const r = JSON.parse(data);
      const ok = r.environment_id === V.environment_id && r.kind === "github" && r.credential === `jwt-for-${serverId}`;
      res.statusCode = ok ? 200 : 401;
      res.end(ok ? JSON.stringify(V.exchange) : "");
    });
  });
  await new Promise((r) => s.server.listen(0, "127.0.0.1", r));
  s.url = `https://127.0.0.1:${s.server.address().port}`;
  return s;
}

const credential = async (aud) => `jwt-for-${aud}`;

test("end to end", async () => {
  const s = await fakeServer("vault.test");
  const bad = await fakeServer("vault.test", false);
  try {
    const c = new Client({ url: s.url, serverId: "vault.test", pin: s.pin, environmentId: V.environment_id, ciKey: V.ci_key, ttlMs: 3_600_000, credential });
    assert.equal(await c.get("DATABASE_PASSWORD"), "hunter2");
    await assert.rejects(c.get("NOPE"), SSMError);
    assert.equal(s.calls, 1); // cached
    for (const [serverId, pin] of [["vault.test", "AAAA"], ["other", s.pin]]) {
      await assert.rejects(new Client({ url: s.url, serverId, pin, environmentId: V.environment_id, ciKey: V.ci_key, credential }).get("DATABASE_PASSWORD"), SSMError);
    }
    await assert.rejects(new Client({ url: bad.url, serverId: "vault.test", pin: bad.pin, environmentId: V.environment_id, ciKey: V.ci_key, credential }).get("DATABASE_PASSWORD"), SSMError);
    assert.throws(() => new Client({ url: "http://x", serverId: "s", pin: "p", environmentId: V.environment_id, ciKey: V.ci_key }), SSMError);
  } finally {
    s.server.close();
    bad.server.close();
  }
});
