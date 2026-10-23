package com.aidigiapps.solosecretsmanager.sdk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Reads secrets from a SoloSecretsManager server inside CI jobs (SDK-01, SEC-MACH-02).
 *
 * <p>The server only returns ciphertext. The job proves who it is with a GitHub Actions OIDC token, gets the
 * environment key wrapped under SSM_CI_KEY, and decrypts in memory. Nothing is written to disk (SDK-06).
 *
 * <pre>String pw = Client.fromEnv().get("DATABASE_PASSWORD");</pre>
 *
 * <p>Pure port of the decrypt subset with the JDK's crypto (SDK-02), checked against
 * testvectors/machine-v1.json (QA-G-03). Secrets are cached for the TTL (SDK-04); a revoked grant stops at the
 * next refresh. ponytail: Java strings can't be wiped; SDK-06 only forbids disk.
 */
public final class Client {
    /** Returns an OIDC token for the audience (the server ID). */
    @FunctionalInterface
    public interface Credential {
        String token(String audience) throws Exception;
    }

    public static final class SSMException extends RuntimeException {
        SSMException(String m) { super("ssm: " + m); }
        SSMException(String m, Throwable cause) { super("ssm: " + m, cause); }
    }

    private static final Base64.Decoder B64D = Base64.getUrlDecoder();
    private static final Base64.Encoder B64E = Base64.getUrlEncoder().withoutPadding();
    private static final int HEADER = 3 + 1 + 1 + 16 + 12;

    private final String host;
    private final int port;
    private final String serverId, pin, environmentId, ciKey;
    private final Duration ttl;
    private final Credential credential;
    private final String kind;
    private final Cloud.Backend cloud;
    private Set<String> pins;
    private Map<String, String> secrets;
    private long fetched;

    public Client(String url, String serverId, String pin, String environmentId, String ciKey, Duration ttl, Credential credential) {
        this(url, serverId, pin, environmentId, ciKey, ttl, credential, "github", null);
    }

    /**
     * kind is "github" or "gitlab" for the CI-key kinds; cloud (Cloud.AWS, Cloud.Azure or Cloud.GCP) replaces the CI key for
     * cloud workloads (SEC-MACH-06/08/09), and ciKey is then unused.
     */
    public Client(String url, String serverId, String pin, String environmentId, String ciKey, Duration ttl, Credential credential,
                  String kind, Cloud.Backend cloud) {
        URI u;
        try { u = URI.create(url == null ? "" : url); } catch (IllegalArgumentException e) { u = null; }
        if (u == null || !"https".equals(u.getScheme()) || u.getHost() == null) throw new SSMException("URL must be https://host[:port]");
        if (empty(serverId) || empty(pin)) throw new SSMException("server ID and pin are required");
        uuid(environmentId);
        if (!"github".equals(kind) && !"gitlab".equals(kind)) throw new SSMException("kind must be github or gitlab");
        if (cloud == null && b64(ciKey == null ? "" : ciKey).length != 48) throw new SSMException("SSM_CI_KEY is missing or malformed");
        this.kind = kind;
        this.cloud = cloud;
        this.host = u.getHost();
        this.port = u.getPort() == -1 ? 443 : u.getPort();
        this.serverId = serverId;
        this.pin = pin;
        this.environmentId = environmentId;
        this.ciKey = ciKey;
        this.ttl = ttl == null ? Duration.ofMinutes(5) : ttl;
        this.credential = credential != null ? credential : "gitlab".equals(kind) ? Client::gitlabToken : Client::githubToken;
    }

    /**
     * Reads SSM_URL, SSM_SERVER_ID, SSM_PIN, SSM_ENVIRONMENT_ID and SSM_CI_KEY; for cloud workloads SSM_AWS_KMS_KEY, SSM_AZURE_KEY
     * (+ SSM_AZURE_AUDIENCE) or SSM_GCP_KMS_KEY instead of SSM_CI_KEY (SDK-09).
     */
    public static Client fromEnv() {
        Map<String, String> e = System.getenv();
        return new Client(e.get("SSM_URL"), e.get("SSM_SERVER_ID"), e.get("SSM_PIN"), e.get("SSM_ENVIRONMENT_ID"), e.get("SSM_CI_KEY"), null, null,
            "true".equals(e.get("GITLAB_CI")) ? "gitlab" : "github", Cloud.fromEnv());
    }

    public String get(String name) {
        Map<String, String> all = all();
        if (!all.containsKey(name)) throw new SSMException("no secret named \"" + name + "\" in this environment");
        return all.get(name);
    }

    public synchronized Map<String, String> all() {
        if (secrets == null || System.nanoTime() - fetched >= ttl.toNanos()) refresh();
        return new HashMap<>(secrets);
    }

    private static boolean empty(String s) { return s == null || s.isEmpty(); }

    private static byte[] b64(String s) {
        try {
            return B64D.decode(s.trim().replaceAll("=+$", ""));
        } catch (IllegalArgumentException e) {
            throw new SSMException("malformed base64", e);
        }
    }

    private static byte[] uuid(String s) {
        try {
            UUID u = UUID.fromString(s);
            return ByteBuffer.allocate(16).putLong(u.getMostSignificantBits()).putLong(u.getLeastSignificantBits()).array();
        } catch (RuntimeException e) {
            throw new SSMException("bad UUID", e);
        }
    }

    // | magic "SSM" | fmt_ver u8 | alg_id u8 | key_id 16B | nonce 12B | ciphertext … | tag 16B |
    // AAD = fmt_ver ‖ alg_id ‖ key_id ‖ object_id ‖ object_revision (u64 big-endian)
    static byte[] open(byte[] keyId, byte[] key, byte[] obj, long revision, byte[] env) {
        if (env.length < HEADER + 16 || env[0] != 'S' || env[1] != 'S' || env[2] != 'M') throw new SSMException("malformed envelope");
        if (env[3] != 1 || env[4] != 1) throw new SSMException("unsupported envelope version or algorithm");
        if (!Arrays.equals(Arrays.copyOfRange(env, 5, 21), keyId)) throw new SSMException("envelope sealed under a different key");
        byte[] aad = ByteBuffer.allocate(42).put((byte) 1).put((byte) 1).put(keyId).put(obj).putLong(revision).array();
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, env, 21, 12));
            c.updateAAD(aad);
            return c.doFinal(env, HEADER, env.length - HEADER);
        } catch (GeneralSecurityException e) {
            throw new SSMException("decryption failed (tampered, swapped or wrong key)", e);
        }
    }

    private static byte[][] unwrap(byte[] keyId, byte[] key, byte[] obj, byte[] env) {
        byte[] p = open(keyId, key, obj, 0, env);
        if (p.length != 48) throw new SSMException("malformed wrapped key");
        byte[][] out = {Arrays.copyOf(p, 16), Arrays.copyOfRange(p, 16, 48)};
        Arrays.fill(p, (byte) 0);
        return out;
    }

    /** Opens the environment key with the CI key, then each item (SEC-MACH-05). Any failure fails the whole call. */
    @SuppressWarnings("unchecked")
    static Map<String, String> decryptExchange(String ciKey, String environmentId, Map<String, Object> exchange) {
        byte[] raw = b64(ciKey);
        if (raw.length != 48) throw new SSMException("SSM_CI_KEY is missing or malformed");
        byte[][] ek = unwrap(Arrays.copyOf(raw, 16), Arrays.copyOfRange(raw, 16, 48), uuid(environmentId), b64((String) exchange.get("wrapped_key")));
        Arrays.fill(raw, (byte) 0);
        return decryptItems(ek, exchange);
    }

    /** What a cloud KMS decrypted: environment ID ‖ key ID ‖ key; it must be this environment's (SEC-MACH-06/08/09). */
    static byte[][] cloudEnvKey(byte[] plain, String environmentId) {
        if (plain.length != 64 || !Arrays.equals(Arrays.copyOf(plain, 16), uuid(environmentId))) {
            throw new SSMException("KMS returned a key for another environment");
        }
        byte[][] k = {Arrays.copyOfRange(plain, 16, 32), Arrays.copyOfRange(plain, 32, 64)};
        Arrays.fill(plain, (byte) 0);
        return k;
    }

    @SuppressWarnings("unchecked")
    static Map<String, String> decryptItems(byte[][] ek, Map<String, Object> exchange) {
        Map<String, String> out = new HashMap<>();
        try {
            for (Object o : (List<Object>) exchange.get("items")) {
                Map<String, Object> it = (Map<String, Object>) o;
                byte[] id = uuid((String) it.get("id"));
                byte[][] ik = unwrap(ek[0], ek[1], id, b64((String) it.get("item_key")));
                byte[] plain = open(ik[0], ik[1], id, ((Number) it.get("revision")).longValue(), b64((String) it.get("payload")));
                Arrays.fill(ik[1], (byte) 0);
                Map<String, Object> p = (Map<String, Object>) Json.parse(new String(plain, StandardCharsets.UTF_8));
                Arrays.fill(plain, (byte) 0);
                String name = p.get("name") instanceof String n ? n : "";
                if (out.containsKey(name)) throw new SSMException("two secrets are named \"" + name + "\"; rename one in the app");
                out.put(name, p.get("secret") instanceof String s ? s : "");
            }
        } catch (ClassCastException | NullPointerException | IllegalArgumentException e) {
            throw new SSMException("malformed exchange", e);
        } finally {
            Arrays.fill(ek[1], (byte) 0);
        }
        return out;
    }

    static String spkiPin(byte[] spkiDer) {
        try {
            return B64E.encodeToString(MessageDigest.getInstance("SHA-256").digest(spkiDer));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** SEC-TLS-05: the identity key matches pin, signed the statement for this server, and attests connPin. */
    @SuppressWarnings("unchecked")
    static Set<String> verifyAttestation(Map<String, Object> a, String pin, String serverId, String connPin) {
        byte[] der, body, sig;
        PublicKey key;
        try {
            der = b64((String) a.get("identity_public_key"));
            body = b64((String) a.get("statement"));
            sig = b64((String) a.get("signature"));
            key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new SSMException("malformed attestation", e);
        }
        boolean ok;
        try {
            Signature v = Signature.getInstance("SHA256withECDSA");
            v.initVerify(key);
            v.update(body);
            ok = key instanceof ECPublicKey && spkiPin(der).equals(pin) && v.verify(sig);
        } catch (GeneralSecurityException e) {
            ok = false;
        }
        if (!ok) throw new SSMException("server identity does not match the pin");
        Map<String, Object> st = (Map<String, Object>) Json.parse(new String(body, StandardCharsets.UTF_8));
        if (!"ssm-tls-attestation-v1".equals(st.get("purpose")) || !serverId.equals(st.get("server_id"))) {
            throw new SSMException("attestation is not for this server");
        }
        Set<String> pins = new HashSet<>();
        if (st.get("tls_pins") instanceof List<?> l) for (Object p : l) pins.add(String.valueOf(p));
        if (!pins.contains(connPin)) throw new SSMException("TLS certificate is not attested by the server identity");
        return pins;
    }

    private record Response(int status, byte[] body, String connPin) {}

    /** One request on a fresh TLS 1.3 connection; the handshake fails unless the certificate's pin is attested. */
    private Response request(String method, String path, byte[] body) throws IOException {
        String[] seen = new String[1];
        Set<String> allowed = pins;
        X509TrustManager tm = new X509TrustManager() { // replaces CA and host name checks with the pin check
            public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException { throw new CertificateException(); }
            public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                seen[0] = spkiPin(chain[0].getPublicKey().getEncoded());
                if (allowed != null && !allowed.contains(seen[0])) throw new CertificateException("ssm: server certificate is not pinned");
            }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        HttpsURLConnection c;
        try {
            SSLContext ctx = SSLContext.getInstance("TLSv1.3");
            ctx.init(null, new TrustManager[] {tm}, null);
            c = (HttpsURLConnection) URI.create("https://" + (host.contains(":") ? "[" + host + "]" : host) + ":" + port + path).toURL().openConnection();
            c.setSSLSocketFactory(ctx.getSocketFactory());
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
        c.setHostnameVerifier((h, s) -> true);
        c.setRequestMethod(method);
        c.setRequestProperty("Connection", "close");
        c.setConnectTimeout(30_000);
        c.setReadTimeout(30_000);
        if (body != null) {
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/json");
            try (OutputStream o = c.getOutputStream()) { o.write(body); }
        }
        int status = c.getResponseCode();
        try (InputStream in = status < 400 ? c.getInputStream() : c.getErrorStream()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            if (in != null) in.transferTo(out);
            return new Response(status, out.toByteArray(), seen[0]);
        } finally {
            c.disconnect();
        }
    }

    @SuppressWarnings("unchecked")
    private void refresh() {
        try {
            if (pins == null) {
                Response r = request("GET", "/v1/tls/attestation", null);
                if (r.status != 200) throw new SSMException("server has no valid TLS attestation");
                pins = verifyAttestation((Map<String, Object>) Json.parse(new String(r.body, StandardCharsets.UTF_8)), pin, serverId, r.connPin);
            }
            String k = cloud != null ? cloud.kind() : kind;
            String cred = cloud != null ? cloud.identity(serverId) : credential.token(serverId);
            byte[] req = ("{\"environment_id\":" + Json.quote(environmentId) + ",\"kind\":" + Json.quote(k) + ",\"credential\":" + Json.quote(cred) + "}")
                .getBytes(StandardCharsets.UTF_8);
            Response r;
            try {
                r = request("POST", "/v1/machine/exchange", req);
            } catch (IOException e) {
                pins = null; // the certificate may have rotated: attest again next time
                throw e;
            }
            if (r.status != 200) throw new SSMException("server refused this machine identity (" + r.status + ")");
            Map<String, Object> ex = (Map<String, Object>) Json.parse(new String(r.body, StandardCharsets.UTF_8));
            secrets = cloud != null ? decryptItems(cloudEnvKey(cloud.decrypt(b64((String) ex.get("wrapped_key"))), environmentId), ex)
                : decryptExchange(ciKey, environmentId, ex);
            fetched = System.nanoTime();
        } catch (SSMException e) {
            throw e;
        } catch (Exception e) {
            throw new SSMException(e.getMessage() == null ? e.toString() : e.getMessage(), e);
        }
    }

    /** The job's ID token, declared with the server ID as audience: {@code id_tokens: SSM_ID_TOKEN: aud: <server ID>}. */
    public static String gitlabToken(String audience) {
        String t = System.getenv("SSM_ID_TOKEN");
        if (empty(t)) throw new SSMException("SSM_ID_TOKEN is not set; declare it under id_tokens with the server ID as aud");
        return t;
    }

    /** Asks the GitHub Actions runner for an OIDC token. The workflow needs {@code permissions: id-token: write}. */
    @SuppressWarnings("unchecked")
    public static String githubToken(String audience) throws Exception {
        String url = System.getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), tok = System.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        if (empty(url) || empty(tok)) throw new SSMException("not in GitHub Actions, or the workflow lacks `permissions: id-token: write`");
        HttpResponse<String> r = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create(url + "&audience=" + URLEncoder.encode(audience, StandardCharsets.UTF_8)))
                .header("Authorization", "Bearer " + tok).timeout(Duration.ofSeconds(30)).build(),
            HttpResponse.BodyHandlers.ofString());
        Object v = r.statusCode() == 200 ? ((Map<String, Object>) Json.parse(r.body())).get("value") : null;
        if (!(v instanceof String s) || s.isEmpty()) throw new SSMException("GitHub did not issue an OIDC token");
        return s;
    }
}
