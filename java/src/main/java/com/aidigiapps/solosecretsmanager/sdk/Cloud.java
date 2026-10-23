package com.aidigiapps.solosecretsmanager.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cloud workload identities without cloud SDKs (SEC-MACH-06/08/09, SDK-09): a small SigV4 signer checked against
 * testvectors/aws-sigv4.json, the AWS credential chain, and the Azure and GCP metadata and KMS REST calls.
 */
public final class Cloud {
    private Cloud() {}

    /** Proves a cloud workload's identity and has its KMS decrypt the environment key. */
    public interface Backend {
        String kind();
        String identity(String serverId) throws Exception;
        byte[] decrypt(byte[] blob) throws Exception;
    }

    static final String STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15";
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();

    static String http(String method, String url, Map<String, String> headers, String body) throws IOException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15))
            .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        headers.forEach((k, v) -> { if (!k.equalsIgnoreCase("Host") && !k.equalsIgnoreCase("Content-Length")) b.header(k, v); });
        HttpResponse<String> r;
        try {
            r = HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
        if (r.statusCode() != 200) {
            String t = r.body();
            throw new IOException(method + " " + url.split("\\?")[0] + ": " + r.statusCode() + " " + t.substring(0, Math.min(500, t.length())).trim());
        }
        return r.body();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> json(String s) { return (Map<String, Object>) Json.parse(s); }

    private static String hex(byte[] b) { return HexFormat.of().formatHex(b); }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hmac(byte[] key, String s) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(s.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** AWS credentials: access key, secret, session token (may be empty). */
    public record Credentials(String key, String secret, String token) {}

    /**
     * Returns the headers to send: the given ones plus Host, Content-Length, X-Amz-Date, the session token and
     * Authorization. Same canonical form as AWS's Go signer (content-length is signed).
     */
    public static Map<String, String> sigv4(String method, String url, String region, String service, Map<String, String> headers, String body,
                                            Credentials c, Instant now) {
        String amz = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC).format(now);
        String day = amz.substring(0, 8);
        URI u = URI.create(url);
        Map<String, String> h = new LinkedHashMap<>(headers);
        h.put("Host", u.getRawAuthority());
        h.put("Content-Length", String.valueOf(body.getBytes(StandardCharsets.UTF_8).length));
        h.put("X-Amz-Date", amz);
        if (c.token() != null && !c.token().isEmpty()) h.put("X-Amz-Security-Token", c.token());
        TreeMap<String, String> canon = new TreeMap<>();
        h.forEach((k, v) -> canon.put(k.toLowerCase(), v.trim().replaceAll("\\s+", " ")));
        String signed = String.join(";", canon.keySet());
        StringBuilder ch = new StringBuilder();
        canon.forEach((k, v) -> ch.append(k).append(':').append(v).append('\n'));
        String path = u.getRawPath() == null || u.getRawPath().isEmpty() ? "/" : u.getRawPath();
        String creq = String.join("\n", method, path, u.getRawQuery() == null ? "" : u.getRawQuery(), ch, signed, hex(sha256(body)));
        String scope = day + "/" + region + "/" + service + "/aws4_request";
        String sts = String.join("\n", "AWS4-HMAC-SHA256", amz, scope, hex(sha256(creq)));
        byte[] k = ("AWS4" + c.secret()).getBytes(StandardCharsets.UTF_8);
        for (String part : new String[] {day, region, service, "aws4_request"}) k = hmac(k, part);
        h.put("Authorization", "AWS4-HMAC-SHA256 Credential=" + c.key() + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + hex(hmac(k, sts)));
        return h;
    }

    private static String env(String k) { String v = System.getenv(k); return v == null ? "" : v; }

    /** Environment, web identity (EKS IRSA), container (ECS, EKS Pod Identity), then EC2 IMDSv2 (SDK-09). */
    @SuppressWarnings("unchecked")
    public static Credentials awsCredentials() throws IOException {
        if (!env("AWS_ACCESS_KEY_ID").isEmpty() && !env("AWS_SECRET_ACCESS_KEY").isEmpty()) {
            return new Credentials(env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY"), env("AWS_SESSION_TOKEN"));
        }
        Map<String, Object> c;
        if (!env("AWS_WEB_IDENTITY_TOKEN_FILE").isEmpty() && !env("AWS_ROLE_ARN").isEmpty()) {
            String q = "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=" + enc(env("AWS_ROLE_ARN"))
                + "&RoleSessionName=" + enc(env("AWS_ROLE_SESSION_NAME").isEmpty() ? "ssm-sdk" : env("AWS_ROLE_SESSION_NAME"))
                + "&WebIdentityToken=" + enc(Files.readString(Path.of(env("AWS_WEB_IDENTITY_TOKEN_FILE"))).trim());
            String sts = !env("AWS_ENDPOINT_URL_STS").isEmpty() ? env("AWS_ENDPOINT_URL_STS")
                : !env("AWS_ENDPOINT_URL").isEmpty() ? env("AWS_ENDPOINT_URL") : "https://sts.amazonaws.com";
            Map<String, Object> x = json(http("POST", sts.replaceAll("/$", "") + "/",
                Map.of("Content-Type", "application/x-www-form-urlencoded", "Accept", "application/json"), q));
            c = (Map<String, Object>) ((Map<String, Object>) ((Map<String, Object>) x.get("AssumeRoleWithWebIdentityResponse"))
                .get("AssumeRoleWithWebIdentityResult")).get("Credentials");
            return new Credentials((String) c.get("AccessKeyId"), (String) c.get("SecretAccessKey"), (String) c.get("SessionToken"));
        }
        if (!env("AWS_CONTAINER_CREDENTIALS_FULL_URI").isEmpty() || !env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").isEmpty()) {
            Map<String, String> hdr = new LinkedHashMap<>();
            if (!env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE").isEmpty()) {
                hdr.put("Authorization", Files.readString(Path.of(env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"))).trim());
            } else if (!env("AWS_CONTAINER_AUTHORIZATION_TOKEN").isEmpty()) {
                hdr.put("Authorization", env("AWS_CONTAINER_AUTHORIZATION_TOKEN"));
            }
            String u = !env("AWS_CONTAINER_CREDENTIALS_FULL_URI").isEmpty() ? env("AWS_CONTAINER_CREDENTIALS_FULL_URI")
                : "http://169.254.170.2" + env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
            c = json(http("GET", u, hdr, null));
        } else {
            String imds = "http://169.254.169.254";
            String t = http("PUT", imds + "/latest/api/token", Map.of("X-aws-ec2-metadata-token-ttl-seconds", "300"), "");
            String role = http("GET", imds + "/latest/meta-data/iam/security-credentials/", Map.of("X-aws-ec2-metadata-token", t), null).trim().split("\\s+")[0];
            c = json(http("GET", imds + "/latest/meta-data/iam/security-credentials/" + role, Map.of("X-aws-ec2-metadata-token", t), null));
        }
        return new Credentials((String) c.get("AccessKeyId"), (String) c.get("SecretAccessKey"), c.get("Token") instanceof String s ? s : "");
    }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }

    public static final class AWS implements Backend {
        final String keyArn, region, sts;
        String kms;

        public AWS(String keyArn, String stsEndpoint) {
            String[] p = keyArn == null ? new String[0] : keyArn.split(":");
            if (p.length < 6 || !p[2].equals("kms") || p[3].isEmpty()) throw new Client.SSMException("SSM_AWS_KMS_KEY must be a KMS key ARN");
            this.keyArn = keyArn;
            this.region = p[3];
            this.sts = (stsEndpoint == null || stsEndpoint.isEmpty() ? "https://sts.amazonaws.com" : stsEndpoint).replaceAll("/$", "");
            String k = !env("AWS_ENDPOINT_URL_KMS").isEmpty() ? env("AWS_ENDPOINT_URL_KMS")
                : !env("AWS_ENDPOINT_URL").isEmpty() ? env("AWS_ENDPOINT_URL") : "https://kms." + region + ".amazonaws.com";
            this.kms = k.replaceAll("/$", "");
        }

        public String kind() { return "aws"; }

        public String identity(String serverId) throws IOException {
            String host = URI.create(sts).getHost();
            String[] parts = host.split("\\.");
            String r = host.startsWith("sts.") && parts.length == 4 ? parts[1] : "us-east-1";
            Map<String, String> h = sigv4("POST", sts + "/", r, "sts", Map.of("Content-Type", "application/x-www-form-urlencoded; charset=utf-8",
                "X-Ssm-Server-Id", serverId), STS_BODY, awsCredentials(), Instant.now());
            h.remove("Host");
            h.remove("Content-Length");
            StringBuilder hs = new StringBuilder("{");
            h.forEach((k, v) -> hs.append(hs.length() > 1 ? "," : "").append(Json.quote(k)).append(':').append(Json.quote(v)));
            String proof = "{\"method\":\"POST\",\"url\":" + Json.quote(sts + "/") + ",\"headers\":" + hs + "},\"body\":" + Json.quote(STS_BODY) + "}";
            return Base64.getUrlEncoder().withoutPadding().encodeToString(proof.getBytes(StandardCharsets.UTF_8));
        }

        public byte[] decrypt(byte[] blob) throws IOException {
            String body = "{\"KeyId\":" + Json.quote(keyArn) + ",\"CiphertextBlob\":\"" + Base64.getEncoder().encodeToString(blob)
                + "\",\"EncryptionAlgorithm\":\"RSAES_OAEP_SHA_256\"}";
            Map<String, String> h = sigv4("POST", kms + "/", region, "kms", Map.of("Content-Type", "application/x-amz-json-1.1",
                "X-Amz-Target", "TrentService.Decrypt"), body, awsCredentials(), Instant.now());
            try {
                return Base64.getDecoder().decode((String) json(http("POST", kms + "/", h, body)).get("Plaintext"));
            } catch (IOException e) {
                throw new IOException("KMS refused to decrypt the environment key: " + e.getMessage(), e);
            }
        }
    }

    public static final class Azure implements Backend {
        String keyUrl;
        final String audience;
        String imds = "http://169.254.169.254";

        public Azure(String keyUrl, String audience) {
            URI u;
            try { u = URI.create(keyUrl == null ? "" : keyUrl); } catch (IllegalArgumentException e) { u = null; }
            if (u == null || !"https".equals(u.getScheme()) || u.getPath() == null || !u.getPath().contains("/keys/")) {
                throw new Client.SSMException("SSM_AZURE_KEY must be a Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>/<version>)");
            }
            if (audience == null || audience.isEmpty()) {
                throw new Client.SSMException("SSM_AZURE_AUDIENCE is required (the application ID URI registered for the server)");
            }
            this.keyUrl = keyUrl.replaceAll("/$", "");
            this.audience = audience;
        }

        public String kind() { return "azure"; }

        String token(String resource) throws IOException {
            String x = !env("IDENTITY_ENDPOINT").isEmpty() && !env("IDENTITY_HEADER").isEmpty() // App Service, Functions
                ? http("GET", env("IDENTITY_ENDPOINT") + "?api-version=2019-08-01&resource=" + enc(resource), Map.of("X-IDENTITY-HEADER", env("IDENTITY_HEADER")), null)
                : http("GET", imds + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" + enc(resource), Map.of("Metadata", "true"), null);
            if (!(json(x).get("access_token") instanceof String t) || t.isEmpty()) throw new IOException("Azure managed identity returned no token");
            return t;
        }

        public String identity(String serverId) throws IOException { return token(audience); }

        public byte[] decrypt(byte[] blob) throws IOException {
            String body = "{\"alg\":\"RSA-OAEP-256\",\"value\":\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(blob) + "\"}";
            try {
                String v = (String) json(http("POST", keyUrl + "/decrypt?api-version=7.4",
                    Map.of("Authorization", "Bearer " + token("https://vault.azure.net"), "Content-Type", "application/json"), body)).get("value");
                return Base64.getUrlDecoder().decode(v.replaceAll("=+$", ""));
            } catch (IOException e) {
                throw new IOException("Key Vault refused to decrypt the environment key: " + e.getMessage(), e);
            }
        }
    }

    public static final class GCP implements Backend {
        static final String SA = "/computeMetadata/v1/instance/service-accounts/default/";
        final String keyVersion;
        String metadata = "http://metadata.google.internal", km = "https://cloudkms.googleapis.com";

        public GCP(String keyVersion) {
            if (keyVersion == null || !keyVersion.startsWith("projects/") || !keyVersion.contains("/cryptoKeyVersions/")) {
                throw new Client.SSMException("SSM_GCP_KMS_KEY must be a key version name (projects/…/cryptoKeys/…/cryptoKeyVersions/N)");
            }
            this.keyVersion = keyVersion;
        }

        public String kind() { return "gcp"; }

        public String identity(String serverId) throws IOException {
            return http("GET", metadata + SA + "identity?format=full&audience=" + enc(serverId), Map.of("Metadata-Flavor", "Google"), null).trim();
        }

        public byte[] decrypt(byte[] blob) throws IOException {
            String at = (String) json(http("GET", metadata + SA + "token", Map.of("Metadata-Flavor", "Google"), null)).get("access_token");
            try {
                String x = http("POST", km + "/v1/" + keyVersion + ":asymmetricDecrypt", Map.of("Authorization", "Bearer " + at, "Content-Type", "application/json"),
                    "{\"ciphertext\":\"" + Base64.getEncoder().encodeToString(blob) + "\"}");
                return Base64.getDecoder().decode((String) json(x).get("plaintext"));
            } catch (IOException e) {
                throw new IOException("Cloud KMS refused to decrypt the environment key: " + e.getMessage(), e);
            }
        }
    }

    /** SSM_AWS_KMS_KEY, SSM_AZURE_KEY (+ SSM_AZURE_AUDIENCE) or SSM_GCP_KMS_KEY; null for the CI-key kinds. */
    public static Backend fromEnv() {
        if (!env("SSM_AWS_KMS_KEY").isEmpty()) return new AWS(env("SSM_AWS_KMS_KEY"), env("SSM_AWS_STS_ENDPOINT"));
        if (!env("SSM_AZURE_KEY").isEmpty()) return new Azure(env("SSM_AZURE_KEY"), env("SSM_AZURE_AUDIENCE"));
        if (!env("SSM_GCP_KMS_KEY").isEmpty()) return new GCP(env("SSM_GCP_KMS_KEY"));
        return null;
    }
}
