package com.aidigiapps.solosecretsmanager.sdk;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;

/** QA-G-03 contract plus an end-to-end run against a fake TLS server. */
@SuppressWarnings("unchecked")
class ClientTest {
    static final Map<String, Object> V;
    static final String RAW;

    static {
        try {
            RAW = Files.readString(Path.of("../testvectors/machine-v1.json"));
            V = (Map<String, Object>) Json.parse(RAW);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static String s(Map<String, Object> m, String k) { return (String) m.get(k); }

    @Test
    void contractAccept() {
        assertEquals(V.get("expected"), Client.decryptExchange(s(V, "ci_key"), s(V, "environment_id"), (Map<String, Object>) V.get("exchange")));
    }

    @Test
    void contractReject() {
        List<Object> rejects = (List<Object>) V.get("reject");
        assertTrue(rejects.size() >= 10);
        for (Object o : rejects) {
            Map<String, Object> r = (Map<String, Object>) o;
            assertThrows(Client.SSMException.class,
                () -> Client.decryptExchange(s(r, "ci_key"), s(r, "environment_id"), (Map<String, Object>) r.get("exchange")), s(r, "name"));
        }
    }

    @Test
    void contractAttestation() {
        Map<String, Object> a = (Map<String, Object>) V.get("attestation");
        assertEquals(new HashSet<>((List<Object>) a.get("pins")),
            Client.verifyAttestation((Map<String, Object>) a.get("attestation"), s(a, "pin"), s(a, "server_id"), s(a, "conn_pin")));
        for (Object o : (List<Object>) V.get("attestation_reject")) {
            Map<String, Object> r = (Map<String, Object>) o;
            assertThrows(Client.SSMException.class,
                () -> Client.verifyAttestation((Map<String, Object>) r.get("attestation"), s(r, "pin"), s(r, "server_id"), s(r, "conn_pin")), s(r, "name"));
        }
    }

    static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    record Fake(HttpsServer server, String url, String pin, AtomicInteger calls) {}

    static Fake fake(String serverId, boolean attestOwnCert) throws Exception {
        Path dir = Files.createTempDirectory("ssm");
        Process p = new ProcessBuilder("sh", "-c",
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout k.pem -out c.pem"
                + " && openssl pkcs12 -export -inkey k.pem -in c.pem -out s.p12 -passout pass:pw")
            .directory(dir.toFile()).redirectErrorStream(true).start();
        p.getInputStream().readAllBytes();
        assertEquals(0, p.waitFor());
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(dir.resolve("s.p12").toFile())) { ks.load(in, "pw".toCharArray()); }
        X509Certificate cert = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "pw".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), null, null);

        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256);
        KeyPair id = g.generateKeyPair();
        byte[] der = id.getPublic().getEncoded();
        String certPin = attestOwnCert ? Client.spkiPin(cert.getPublicKey().getEncoded()) : "someone-else";
        byte[] body = ("{\"purpose\":\"ssm-tls-attestation-v1\",\"server_id\":" + Json.quote(serverId) + ",\"tls_pins\":[" + Json.quote(certPin) + "]}")
            .getBytes(StandardCharsets.UTF_8);
        Signature sg = Signature.getInstance("SHA256withECDSA");
        sg.initSign(id.getPrivate());
        sg.update(body);
        byte[] attestation = ("{\"identity_public_key\":\"" + B64.encodeToString(der) + "\",\"statement\":\"" + B64.encodeToString(body)
            + "\",\"signature\":\"" + B64.encodeToString(sg.sign()) + "\"}").getBytes(StandardCharsets.UTF_8);
        String exchange = RAW.substring(RAW.indexOf("{", RAW.indexOf("\"exchange\"")));
        exchange = exchange.substring(0, matchingBrace(exchange) + 1);
        byte[] ex = exchange.getBytes(StandardCharsets.UTF_8);

        AtomicInteger calls = new AtomicInteger();
        HttpsServer srv = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.setHttpsConfigurator(new HttpsConfigurator(ctx));
        srv.createContext("/v1/tls/attestation", x -> { x.sendResponseHeaders(200, attestation.length); x.getResponseBody().write(attestation); x.close(); });
        srv.createContext("/v1/machine/exchange", x -> {
            calls.incrementAndGet();
            Map<String, Object> r = (Map<String, Object>) Json.parse(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            boolean ok = V.get("environment_id").equals(r.get("environment_id")) && "github".equals(r.get("kind")) && ("jwt-for-" + serverId).equals(r.get("credential"));
            if (ok) { x.sendResponseHeaders(200, ex.length); x.getResponseBody().write(ex); } else x.sendResponseHeaders(401, -1);
            x.close();
        });
        srv.start();
        String pin = Client.spkiPin(der);
        return new Fake(srv, "https://127.0.0.1:" + srv.getAddress().getPort(), pin, calls);
    }

    static int matchingBrace(String s) {
        int depth = 0;
        boolean str = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (str) { if (c == '\\') i++; else if (c == '"') str = false; continue; }
            if (c == '"') str = true;
            else if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return i;
        }
        throw new IllegalStateException();
    }

    @Test
    void endToEnd() throws Exception {
        Client.Credential cred = aud -> "jwt-for-" + aud;
        Fake s = fake("vault.test", true), bad = fake("vault.test", false);
        try {
            Client c = new Client(s.url, "vault.test", s.pin, s(V, "environment_id"), s(V, "ci_key"), Duration.ofHours(1), cred);
            assertEquals("hunter2", c.get("DATABASE_PASSWORD"));
            assertThrows(Client.SSMException.class, () -> c.get("NOPE"));
            assertEquals(1, s.calls.get()); // cached
            for (String[] w : new String[][] {{"vault.test", "AAAA"}, {"other", s.pin}}) {
                assertThrows(Client.SSMException.class,
                    () -> new Client(s.url, w[0], w[1], s(V, "environment_id"), s(V, "ci_key"), null, cred).get("DATABASE_PASSWORD"));
            }
            assertThrows(Client.SSMException.class,
                () -> new Client(bad.url, "vault.test", bad.pin, s(V, "environment_id"), s(V, "ci_key"), null, cred).get("DATABASE_PASSWORD"));
            assertThrows(Client.SSMException.class, () -> new Client("http://x", "s", "p", s(V, "environment_id"), s(V, "ci_key"), null, null));
        } finally {
            s.server.stop(0);
            bad.server.stop(0);
        }
    }
}
