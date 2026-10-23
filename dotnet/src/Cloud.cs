// Cloud workload identities without cloud SDKs (SEC-MACH-06/08/09, SDK-09): a small SigV4 signer checked against
// testvectors/aws-sigv4.json, the AWS credential chain, and the Azure and GCP metadata and KMS REST calls.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SoloSecretsManager.Sdk;

/// <summary>Proves a cloud workload's identity and has its KMS decrypt the environment key.</summary>
public interface ICloudBackend
{
    string Kind { get; }
    Task<string> IdentityAsync(string serverId);
    Task<byte[]> DecryptAsync(byte[] blob);
}

public static class Cloud
{
    internal const string StsBody = "Action=GetCallerIdentity&Version=2011-06-15";
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    internal static async Task<string> HttpAsync(string method, string url, IDictionary<string, string>? headers = null, string? body = null)
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), url);
        if (body is not null) req.Content = new StringContent(body, Encoding.UTF8);
        foreach (var (k, v) in headers ?? new Dictionary<string, string>())
        {
            if (k.Equals("Host", StringComparison.OrdinalIgnoreCase) || k.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
            if (k.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                req.Content ??= new StringContent("");
                req.Content.Headers.Remove("Content-Type");
                req.Content.Headers.TryAddWithoutValidation("Content-Type", v); // exactly as signed
            }
            else req.Headers.TryAddWithoutValidation(k, v);
        }
        HttpResponseMessage r;
        try { r = await Http.SendAsync(req); }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { throw new SSMException($"{method} {url.Split('?')[0]}: {e.Message}", e); }
        using (r)
        {
            var text = await r.Content.ReadAsStringAsync();
            if (!r.IsSuccessStatusCode) throw new SSMException($"{method} {url.Split('?')[0]}: {(int)r.StatusCode} {text[..Math.Min(500, text.Length)].Trim()}");
            return text;
        }
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    private static byte[] Hmac(byte[] k, string s) => HMACSHA256.HashData(k, Encoding.UTF8.GetBytes(s));

    public sealed record Credentials(string Key, string Secret, string Token);

    /// <summary>
    /// The headers to send: the given ones plus Host, Content-Length, X-Amz-Date, the session token and Authorization.
    /// Same canonical form as AWS's Go signer (content-length is signed).
    /// </summary>
    public static Dictionary<string, string> SigV4(string method, string url, string region, string service, IDictionary<string, string> headers,
                                                   string body, Credentials c, DateTime now)
    {
        var amz = now.ToUniversalTime().ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var day = amz[..8];
        var u = new Uri(url);
        var h = new Dictionary<string, string>(headers)
        {
            ["Host"] = u.IsDefaultPort ? u.Host : $"{u.Host}:{u.Port}",
            ["Content-Length"] = Encoding.UTF8.GetByteCount(body).ToString(CultureInfo.InvariantCulture),
            ["X-Amz-Date"] = amz,
        };
        if (!string.IsNullOrEmpty(c.Token)) h["X-Amz-Security-Token"] = c.Token;
        var canon = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in h) canon[k.ToLowerInvariant()] = string.Join(' ', v.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        var signed = string.Join(';', canon.Keys);
        var creq = string.Join('\n', method, string.IsNullOrEmpty(u.AbsolutePath) ? "/" : u.AbsolutePath, u.Query.TrimStart('?'),
            string.Concat(canon.Select(kv => $"{kv.Key}:{kv.Value}\n")), signed, Hex(SHA256.HashData(Encoding.UTF8.GetBytes(body))));
        var scope = $"{day}/{region}/{service}/aws4_request";
        var sts = string.Join('\n', "AWS4-HMAC-SHA256", amz, scope, Hex(SHA256.HashData(Encoding.UTF8.GetBytes(creq))));
        var key = Encoding.UTF8.GetBytes("AWS4" + c.Secret);
        foreach (var part in new[] { day, region, service, "aws4_request" }) key = Hmac(key, part);
        h["Authorization"] = $"AWS4-HMAC-SHA256 Credential={c.Key}/{scope}, SignedHeaders={signed}, Signature={Hex(Hmac(key, sts))}";
        return h;
    }

    private static string Env(string k) => Environment.GetEnvironmentVariable(k) ?? "";

    /// <summary>Environment, web identity (EKS IRSA), container (ECS, EKS Pod Identity), then EC2 IMDSv2 (SDK-09).</summary>
    public static async Task<Credentials> AwsCredentialsAsync()
    {
        if (Env("AWS_ACCESS_KEY_ID") != "" && Env("AWS_SECRET_ACCESS_KEY") != "")
            return new(Env("AWS_ACCESS_KEY_ID"), Env("AWS_SECRET_ACCESS_KEY"), Env("AWS_SESSION_TOKEN"));
        JsonNode c;
        if (Env("AWS_WEB_IDENTITY_TOKEN_FILE") != "" && Env("AWS_ROLE_ARN") != "")
        {
            var q = "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=" + Uri.EscapeDataString(Env("AWS_ROLE_ARN"))
                + "&RoleSessionName=" + Uri.EscapeDataString(Env("AWS_ROLE_SESSION_NAME") is "" ? "ssm-sdk" : Env("AWS_ROLE_SESSION_NAME"))
                + "&WebIdentityToken=" + Uri.EscapeDataString(File.ReadAllText(Env("AWS_WEB_IDENTITY_TOKEN_FILE")).Trim());
            var sts = Env("AWS_ENDPOINT_URL_STS") is not "" and var s ? s : Env("AWS_ENDPOINT_URL") is not "" and var g ? g : "https://sts.amazonaws.com";
            var x = JsonNode.Parse(await HttpAsync("POST", sts.TrimEnd('/') + "/",
                new Dictionary<string, string> { ["Content-Type"] = "application/x-www-form-urlencoded", ["Accept"] = "application/json" }, q))!;
            c = x["AssumeRoleWithWebIdentityResponse"]!["AssumeRoleWithWebIdentityResult"]!["Credentials"]!;
            return new((string)c["AccessKeyId"]!, (string)c["SecretAccessKey"]!, (string)c["SessionToken"]!);
        }
        if (Env("AWS_CONTAINER_CREDENTIALS_FULL_URI") != "" || Env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "")
        {
            var hdr = new Dictionary<string, string>();
            if (Env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") != "") hdr["Authorization"] = File.ReadAllText(Env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")).Trim();
            else if (Env("AWS_CONTAINER_AUTHORIZATION_TOKEN") != "") hdr["Authorization"] = Env("AWS_CONTAINER_AUTHORIZATION_TOKEN");
            var u = Env("AWS_CONTAINER_CREDENTIALS_FULL_URI") is not "" and var f ? f : "http://169.254.170.2" + Env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
            c = JsonNode.Parse(await HttpAsync("GET", u, hdr))!;
        }
        else
        {
            const string imds = "http://169.254.169.254";
            var t = await HttpAsync("PUT", imds + "/latest/api/token", new Dictionary<string, string> { ["X-aws-ec2-metadata-token-ttl-seconds"] = "300" }, "");
            var th = new Dictionary<string, string> { ["X-aws-ec2-metadata-token"] = t };
            var role = (await HttpAsync("GET", imds + "/latest/meta-data/iam/security-credentials/", th)).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[0];
            c = JsonNode.Parse(await HttpAsync("GET", imds + "/latest/meta-data/iam/security-credentials/" + role, th))!;
        }
        return new((string)c["AccessKeyId"]!, (string)c["SecretAccessKey"]!, (string?)c["Token"] ?? "");
    }

    public sealed class Aws : ICloudBackend
    {
        internal readonly string KeyArn, Region, Sts;
        internal string Kms;

        public Aws(string? keyArn, string? stsEndpoint = null)
        {
            var p = (keyArn ?? "").Split(':');
            if (p.Length < 6 || p[2] != "kms" || p[3] == "") throw new SSMException("SSM_AWS_KMS_KEY must be a KMS key ARN");
            (KeyArn, Region) = (keyArn!, p[3]);
            Sts = (string.IsNullOrEmpty(stsEndpoint) ? "https://sts.amazonaws.com" : stsEndpoint).TrimEnd('/');
            Kms = (Env("AWS_ENDPOINT_URL_KMS") is not "" and var k ? k : Env("AWS_ENDPOINT_URL") is not "" and var g ? g : $"https://kms.{Region}.amazonaws.com").TrimEnd('/');
        }

        public string Kind => "aws";

        public async Task<string> IdentityAsync(string serverId)
        {
            var host = new Uri(Sts).Host;
            var parts = host.Split('.');
            var region = host.StartsWith("sts.") && parts.Length == 4 ? parts[1] : "us-east-1";
            var h = SigV4("POST", Sts + "/", region, "sts", new Dictionary<string, string>
                { ["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8", ["X-Ssm-Server-Id"] = serverId }, StsBody, await AwsCredentialsAsync(), DateTime.UtcNow);
            h.Remove("Host");
            h.Remove("Content-Length");
            var proof = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object> { ["method"] = "POST", ["url"] = Sts + "/", ["headers"] = h, ["body"] = StsBody });
            return Convert.ToBase64String(proof).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public async Task<byte[]> DecryptAsync(byte[] blob)
        {
            var body = JsonSerializer.Serialize(new Dictionary<string, string>
                { ["KeyId"] = KeyArn, ["CiphertextBlob"] = Convert.ToBase64String(blob), ["EncryptionAlgorithm"] = "RSAES_OAEP_SHA_256" });
            var h = SigV4("POST", Kms + "/", Region, "kms", new Dictionary<string, string>
                { ["Content-Type"] = "application/x-amz-json-1.1", ["X-Amz-Target"] = "TrentService.Decrypt" }, body, await AwsCredentialsAsync(), DateTime.UtcNow);
            try { return Convert.FromBase64String((string)JsonNode.Parse(await HttpAsync("POST", Kms + "/", h, body))!["Plaintext"]!); }
            catch (SSMException e) { throw new SSMException("KMS refused to decrypt the environment key: " + e.Message, e); }
        }
    }

    public sealed class Azure : ICloudBackend
    {
        internal string KeyUrl;
        internal readonly string Audience;
        internal string Imds = "http://169.254.169.254";

        public Azure(string? keyUrl, string? audience)
        {
            if (!Uri.TryCreate(keyUrl, UriKind.Absolute, out var u) || u.Scheme != "https" || !u.AbsolutePath.Contains("/keys/"))
                throw new SSMException("SSM_AZURE_KEY must be a Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>/<version>)");
            if (string.IsNullOrEmpty(audience)) throw new SSMException("SSM_AZURE_AUDIENCE is required (the application ID URI registered for the server)");
            (KeyUrl, Audience) = (keyUrl!.TrimEnd('/'), audience);
        }

        public string Kind => "azure";

        internal async Task<string> TokenAsync(string resource)
        {
            var x = Env("IDENTITY_ENDPOINT") != "" && Env("IDENTITY_HEADER") != "" // App Service, Functions
                ? await HttpAsync("GET", $"{Env("IDENTITY_ENDPOINT")}?api-version=2019-08-01&resource={Uri.EscapeDataString(resource)}",
                    new Dictionary<string, string> { ["X-IDENTITY-HEADER"] = Env("IDENTITY_HEADER") })
                : await HttpAsync("GET", $"{Imds}/metadata/identity/oauth2/token?api-version=2018-02-01&resource={Uri.EscapeDataString(resource)}",
                    new Dictionary<string, string> { ["Metadata"] = "true" });
            return (string?)JsonNode.Parse(x)?["access_token"] is { Length: > 0 } t ? t : throw new SSMException("Azure managed identity returned no token");
        }

        public Task<string> IdentityAsync(string serverId) => TokenAsync(Audience);

        public async Task<byte[]> DecryptAsync(byte[] blob)
        {
            var value = Convert.ToBase64String(blob).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            try
            {
                var v = (string)JsonNode.Parse(await HttpAsync("POST", KeyUrl + "/decrypt?api-version=7.4", new Dictionary<string, string>
                    { ["Authorization"] = "Bearer " + await TokenAsync("https://vault.azure.net"), ["Content-Type"] = "application/json" },
                    JsonSerializer.Serialize(new Dictionary<string, string> { ["alg"] = "RSA-OAEP-256", ["value"] = value })))!["value"]!;
                v = v.Replace('-', '+').Replace('_', '/');
                return Convert.FromBase64String(v + new string('=', (4 - v.Length % 4) % 4));
            }
            catch (SSMException e) { throw new SSMException("Key Vault refused to decrypt the environment key: " + e.Message, e); }
        }
    }

    public sealed class Gcp : ICloudBackend
    {
        private const string Sa = "/computeMetadata/v1/instance/service-accounts/default/";
        internal readonly string KeyVersion;
        internal string Metadata = "http://metadata.google.internal", Km = "https://cloudkms.googleapis.com";

        public Gcp(string? keyVersion)
        {
            if (keyVersion is null || !keyVersion.StartsWith("projects/") || !keyVersion.Contains("/cryptoKeyVersions/"))
                throw new SSMException("SSM_GCP_KMS_KEY must be a key version name (projects/…/cryptoKeys/…/cryptoKeyVersions/N)");
            KeyVersion = keyVersion;
        }

        public string Kind => "gcp";

        public async Task<string> IdentityAsync(string serverId) =>
            (await HttpAsync("GET", $"{Metadata}{Sa}identity?format=full&audience={Uri.EscapeDataString(serverId)}",
                new Dictionary<string, string> { ["Metadata-Flavor"] = "Google" })).Trim();

        public async Task<byte[]> DecryptAsync(byte[] blob)
        {
            var at = (string)JsonNode.Parse(await HttpAsync("GET", Metadata + Sa + "token", new Dictionary<string, string> { ["Metadata-Flavor"] = "Google" }))!["access_token"]!;
            try
            {
                var x = await HttpAsync("POST", $"{Km}/v1/{KeyVersion}:asymmetricDecrypt",
                    new Dictionary<string, string> { ["Authorization"] = "Bearer " + at, ["Content-Type"] = "application/json" },
                    JsonSerializer.Serialize(new Dictionary<string, string> { ["ciphertext"] = Convert.ToBase64String(blob) }));
                return Convert.FromBase64String((string)JsonNode.Parse(x)!["plaintext"]!);
            }
            catch (SSMException e) { throw new SSMException("Cloud KMS refused to decrypt the environment key: " + e.Message, e); }
        }
    }

    /// <summary>SSM_AWS_KMS_KEY, SSM_AZURE_KEY (+ SSM_AZURE_AUDIENCE) or SSM_GCP_KMS_KEY; null for the CI-key kinds.</summary>
    public static ICloudBackend? FromEnv() =>
        Env("SSM_AWS_KMS_KEY") != "" ? new Aws(Env("SSM_AWS_KMS_KEY"), Env("SSM_AWS_STS_ENDPOINT"))
        : Env("SSM_AZURE_KEY") != "" ? new Azure(Env("SSM_AZURE_KEY"), Env("SSM_AZURE_AUDIENCE"))
        : Env("SSM_GCP_KMS_KEY") != "" ? new Gcp(Env("SSM_GCP_KMS_KEY"))
        : null;
}
