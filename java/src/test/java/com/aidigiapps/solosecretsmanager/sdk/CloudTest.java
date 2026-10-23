package com.aidigiapps.solosecretsmanager.sdk;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/** SDK-09: SigV4 matches AWS's Go signer; Azure/GCP REST calls; AWS against floci (SSM_TEST_FLOCI=1). */
@SuppressWarnings("unchecked")
class CloudTest {
    static final byte[] PLAIN = "environment-id-key-id-and-key-bytes-sixty-four-bytes-long......".getBytes(StandardCharsets.UTF_8);
    static final OAEPParameterSpec OAEP = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    static byte[] rsa(int mode, java.security.Key k, byte[] in) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(mode, k, OAEP);
        return c.doFinal(in);
    }

    @Test
    void sigv4Vectors() throws Exception {
        Map<String, Object> v = (Map<String, Object>) Json.parse(Files.readString(Path.of("../testvectors/aws-sigv4.json")));
        Cloud.Credentials c = new Cloud.Credentials((String) v.get("access_key_id"), (String) v.get("secret_access_key"), (String) v.get("session_token"));
        for (Object o : (List<Object>) v.get("cases")) {
            Map<String, Object> t = (Map<String, Object>) o;
            Map<String, String> h = Cloud.sigv4((String) t.get("method"), (String) t.get("url"), (String) t.get("region"), (String) t.get("service"),
                (Map<String, String>) (Map<?, ?>) t.get("headers"), (String) t.get("body"), c, Instant.parse((String) v.get("time")));
            ((Map<String, Object>) t.get("signed")).forEach((k, want) -> assertEquals(want, h.get(k), t.get("name") + ": " + k));
        }
    }

    @Test
    void cloudEnvKey() {
        String env = "e0e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0";
        byte[] good = new byte[64];
        for (int i = 0; i < 16; i++) good[i] = (byte) 0xe0;
        for (int i = 16; i < 64; i++) good[i] = (byte) (i - 16);
        assertEquals(15, Client.cloudEnvKey(good.clone(), env)[0][15]);
        assertThrows(Client.SSMException.class, () -> Client.cloudEnvKey(good.clone(), "e1e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0"));
    }

    @Test
    void azureAndGcp() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        byte[] blob = rsa(Cipher.ENCRYPT_MODE, kp.getPublic(), PLAIN);
        List<String> seen = new ArrayList<>();
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/", x -> {
            URI u = x.getRequestURI();
            seen.add(u.toString());
            String q = u.getRawQuery() == null ? "" : java.net.URLDecoder.decode(u.getRawQuery(), StandardCharsets.UTF_8);
            String auth = x.getRequestHeaders().getFirst("Authorization");
            String body = new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String out = null;
            try {
                if (u.getPath().equals("/metadata/identity/oauth2/token") && "true".equals(x.getRequestHeaders().getFirst("Metadata"))) {
                    out = "{\"access_token\":\"az-" + q.replaceAll(".*resource=", "") + "\"}";
                } else if (u.getPath().endsWith("/identity") && "Google".equals(x.getRequestHeaders().getFirst("Metadata-Flavor"))) {
                    out = "gcp-" + q.replaceAll(".*audience=", "") + "-" + (q.contains("format=full") ? "full" : "");
                } else if (u.getPath().endsWith("/token") && "Google".equals(x.getRequestHeaders().getFirst("Metadata-Flavor"))) {
                    out = "{\"access_token\":\"gcp-at\"}";
                } else if (u.getPath().endsWith("/decrypt") && "Bearer az-https://vault.azure.net".equals(auth)) {
                    Map<String, Object> b = (Map<String, Object>) Json.parse(body);
                    if ("RSA-OAEP-256".equals(b.get("alg"))) out = "{\"value\":\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(
                        rsa(Cipher.DECRYPT_MODE, kp.getPrivate(), Base64.getUrlDecoder().decode((String) b.get("value")))) + "\"}";
                } else if (u.getPath().endsWith(":asymmetricDecrypt") && "Bearer gcp-at".equals(auth)) {
                    Map<String, Object> b = (Map<String, Object>) Json.parse(body);
                    out = "{\"plaintext\":\"" + Base64.getEncoder().encodeToString(
                        rsa(Cipher.DECRYPT_MODE, kp.getPrivate(), Base64.getDecoder().decode((String) b.get("ciphertext")))) + "\"}";
                }
            } catch (Exception e) {
                out = null;
            }
            byte[] r = out == null ? new byte[0] : out.getBytes(StandardCharsets.UTF_8);
            x.sendResponseHeaders(out == null ? 403 : 200, r.length == 0 ? -1 : r.length);
            if (r.length > 0) x.getResponseBody().write(r);
            x.close();
        });
        srv.start();
        String base = "http://127.0.0.1:" + srv.getAddress().getPort();
        try {
            Cloud.Azure az = new Cloud.Azure("https://v.vault.azure.net/keys/ssm/1", "api://ssm-vault");
            az.imds = base;
            assertEquals("az-api://ssm-vault", az.identity("vault.test")); // the registered audience, not the server ID
            az.keyUrl = base + "/keys/ssm/1";
            assertArrayEquals(PLAIN, az.decrypt(blob));
            Cloud.GCP gc = new Cloud.GCP("projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1");
            gc.metadata = base;
            gc.km = base;
            assertEquals("gcp-vault.test-full", gc.identity("vault.test"));
            assertArrayEquals(PLAIN, gc.decrypt(blob));
            assertTrue(seen.contains("/v1/projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1:asymmetricDecrypt"), seen.toString());
        } finally {
            srv.stop(0);
        }
        assertThrows(Client.SSMException.class, () -> new Cloud.Azure("http://v/keys/k", "a"));
        assertThrows(Client.SSMException.class, () -> new Cloud.Azure("https://v.vault.azure.net/keys/k/1", ""));
        assertThrows(Client.SSMException.class, () -> new Cloud.GCP("k"));
        assertThrows(Client.SSMException.class, () -> new Cloud.AWS("x", ""));
    }

    static String aws(Map<String, String> env, String... args) throws Exception {
        List<String> cmd = new ArrayList<>(List.of("aws", "--endpoint-url", "http://localhost:4566", "--output", "text"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().putAll(env);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        assertEquals(0, p.waitFor(), String.join(" ", args));
        return out;
    }

    /** The JVM can't change its own environment, so this runs with floci's root keys as the workload's credentials. */
    @Test
    @EnabledIfEnvironmentVariable(named = "SSM_TEST_FLOCI", matches = ".+")
    void awsAgainstFloci() throws Exception {
        Map<String, String> env = Map.of("AWS_ACCESS_KEY_ID", "test", "AWS_SECRET_ACCESS_KEY", "test", "AWS_DEFAULT_REGION", "us-east-1");
        String arn = aws(env, "kms", "create-key", "--key-spec", "RSA_2048", "--key-usage", "ENCRYPT_DECRYPT", "--query", "KeyMetadata.Arn");
        PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(
            Base64.getDecoder().decode(aws(env, "kms", "get-public-key", "--key-id", arn, "--query", "PublicKey"))));
        Cloud.AWS a = new Cloud.AWS(arn, "http://localhost:4566");
        a.kms = "http://localhost:4566";
        Cloud.Credentials c = new Cloud.Credentials("test", "test", "");
        Map<String, String> h = Cloud.sigv4("POST", "http://localhost:4566/", "us-east-1", "sts",
            Map.of("Content-Type", "application/x-www-form-urlencoded; charset=utf-8", "X-Ssm-Server-Id", "vault.test"), Cloud.STS_BODY, c, Instant.now());
        assertTrue(Cloud.http("POST", "http://localhost:4566/", h, Cloud.STS_BODY).contains("<Arn>"));
        if (System.getenv("AWS_ACCESS_KEY_ID") != null) assertArrayEquals(PLAIN, a.decrypt(rsa(Cipher.ENCRYPT_MODE, pub, PLAIN)));
    }
}
