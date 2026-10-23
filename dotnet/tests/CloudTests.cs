// SDK-09: SigV4 matches AWS's Go signer; Azure/GCP REST calls; AWS against floci (SSM_TEST_FLOCI=1).
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using SoloSecretsManager.Sdk;

public class CloudTests
{
    static readonly byte[] Plain = Encoding.UTF8.GetBytes("environment-id-key-id-and-key-bytes-sixty-four-bytes-long......");

    static string Root()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (!Directory.Exists(Path.Combine(d!.FullName, "testvectors"))) d = d.Parent;
        return d.FullName;
    }

    static string B64U(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    static byte[] UnB64U(string s) { s = s.Replace('-', '+').Replace('_', '/'); return Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4)); }

    [Fact]
    public void SigV4Vectors()
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(Root(), "testvectors/aws-sigv4.json")))!;
        var c = new Cloud.Credentials((string)v["access_key_id"]!, (string)v["secret_access_key"]!, (string)v["session_token"]!);
        var now = DateTime.Parse((string)v["time"]!, null, System.Globalization.DateTimeStyles.AdjustToUniversal);
        foreach (var t in v["cases"]!.AsArray())
        {
            var hdr = t!["headers"]!.AsObject().ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
            var h = Cloud.SigV4((string)t["method"]!, (string)t["url"]!, (string)t["region"]!, (string)t["service"]!, hdr, (string)t["body"]!, c, now);
            foreach (var (k, want) in t["signed"]!.AsObject()) Assert.Equal((string)want!, h[k]);
        }
    }

    [Fact]
    public void CloudEnvKey()
    {
        const string env = "e0e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0";
        byte[] Good() => Enumerable.Repeat((byte)0xe0, 16).Concat(Enumerable.Range(0, 48).Select(i => (byte)i)).ToArray();
        Assert.Equal(15, Client.CloudEnvKey(Good(), env).Id[15]);
        Assert.Throws<SSMException>(() => Client.CloudEnvKey(Good(), "e1e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0"));
    }

    [Fact]
    public async Task AzureAndGcp()
    {
        using var rsa = RSA.Create(2048);
        var blob = rsa.Encrypt(Plain, RSAEncryptionPadding.OaepSHA256);
        var seen = new List<string>();
        var l = new HttpListener();
        var port = 47000 + Random.Shared.Next(2000);
        l.Prefixes.Add($"http://127.0.0.1:{port}/");
        l.Start();
        var serve = Task.Run(async () =>
        {
            while (l.IsListening)
            {
                HttpListenerContext x;
                try { x = await l.GetContextAsync(); } catch { return; }
                var u = x.Request.Url!;
                seen.Add(u.PathAndQuery);
                var q = System.Web.HttpUtility.ParseQueryString(u.Query);
                var auth = x.Request.Headers["Authorization"];
                var body = await new StreamReader(x.Request.InputStream).ReadToEndAsync();
                string? outp = null;
                if (u.AbsolutePath == "/metadata/identity/oauth2/token" && x.Request.Headers["Metadata"] == "true") outp = $"{{\"access_token\":\"az-{q["resource"]}\"}}";
                else if (u.AbsolutePath.EndsWith("/identity") && x.Request.Headers["Metadata-Flavor"] == "Google") outp = $"gcp-{q["audience"]}-{q["format"]}";
                else if (u.AbsolutePath.EndsWith("/token") && x.Request.Headers["Metadata-Flavor"] == "Google") outp = "{\"access_token\":\"gcp-at\"}";
                else if (u.AbsolutePath.EndsWith("/decrypt") && auth == "Bearer az-https://vault.azure.net" && (string?)JsonNode.Parse(body)?["alg"] == "RSA-OAEP-256")
                    outp = $"{{\"value\":\"{B64U(rsa.Decrypt(UnB64U((string)JsonNode.Parse(body)!["value"]!), RSAEncryptionPadding.OaepSHA256))}\"}}";
                else if (u.AbsolutePath.EndsWith(":asymmetricDecrypt") && auth == "Bearer gcp-at")
                    outp = $"{{\"plaintext\":\"{Convert.ToBase64String(rsa.Decrypt(Convert.FromBase64String((string)JsonNode.Parse(body)!["ciphertext"]!), RSAEncryptionPadding.OaepSHA256))}\"}}";
                x.Response.StatusCode = outp is null ? 403 : 200;
                if (outp is not null) await x.Response.OutputStream.WriteAsync(Encoding.UTF8.GetBytes(outp));
                x.Response.Close();
            }
        });
        var b = $"http://127.0.0.1:{port}";
        try
        {
            var az = new Cloud.Azure("https://v.vault.azure.net/keys/ssm/1", "api://ssm-vault") { Imds = b, KeyUrl = b + "/keys/ssm/1" };
            Assert.Equal("az-api://ssm-vault", await az.IdentityAsync("vault.test")); // the registered audience, not the server ID
            Assert.Equal(Plain, await az.DecryptAsync(blob));
            var g = new Cloud.Gcp("projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1") { Metadata = b, Km = b };
            Assert.Equal("gcp-vault.test-full", await g.IdentityAsync("vault.test"));
            Assert.Equal(Plain, await g.DecryptAsync(blob));
            Assert.Contains("/v1/projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1:asymmetricDecrypt", seen);
        }
        finally { l.Stop(); }
        Assert.Throws<SSMException>(() => new Cloud.Azure("http://v/keys/k", "a"));
        Assert.Throws<SSMException>(() => new Cloud.Azure("https://v.vault.azure.net/keys/k/1", ""));
        Assert.Throws<SSMException>(() => new Cloud.Gcp("k"));
        Assert.Throws<SSMException>(() => new Cloud.Aws("x"));
    }

    [Fact]
    public async Task AwsAgainstFloci()
    {
        if (Environment.GetEnvironmentVariable("SSM_TEST_FLOCI") is null) return; // needs floci running
        const string ep = "http://localhost:4566";
        string Aws(params string[] a)
        {
            var psi = new System.Diagnostics.ProcessStartInfo("aws", new[] { "--endpoint-url", ep, "--output", "text" }.Concat(a)) { RedirectStandardOutput = true };
            foreach (var (k, v) in new[] { ("AWS_ACCESS_KEY_ID", "test"), ("AWS_SECRET_ACCESS_KEY", "test"), ("AWS_DEFAULT_REGION", "us-east-1") }) psi.Environment[k] = v;
            using var p = System.Diagnostics.Process.Start(psi)!;
            var o = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit();
            Assert.Equal(0, p.ExitCode);
            return o;
        }
        var arn = Aws("kms", "create-key", "--key-spec", "RSA_2048", "--key-usage", "ENCRYPT_DECRYPT", "--query", "KeyMetadata.Arn");
        using var pub = RSA.Create();
        pub.ImportSubjectPublicKeyInfo(Convert.FromBase64String(Aws("kms", "get-public-key", "--key-id", arn, "--query", "PublicKey")), out _);
        var role = $"ssm-dotnet-{DateTime.UtcNow.Ticks}";
        Aws("iam", "create-role", "--role-name", role, "--assume-role-policy-document",
            "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"sts:AssumeRole\"}]}");
        var f = Aws("sts", "assume-role", "--role-arn", $"arn:aws:iam::000000000000:role/{role}", "--role-session-name", "ci",
            "--query", "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        Environment.SetEnvironmentVariable("AWS_ACCESS_KEY_ID", f[0]);
        Environment.SetEnvironmentVariable("AWS_SECRET_ACCESS_KEY", f[1]);
        Environment.SetEnvironmentVariable("AWS_SESSION_TOKEN", f[2]);
        var a = new Cloud.Aws(arn, ep) { Kms = ep };
        var proof = JsonNode.Parse(UnB64U(await a.IdentityAsync("vault.test")))!;
        var headers = proof["headers"]!.AsObject().ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
        Assert.Contains("x-ssm-server-id", headers["Authorization"]);
        Assert.Contains($"assumed-role/{role}/ci", await Cloud.HttpAsync("POST", ep + "/", headers, (string)proof["body"]!));
        Assert.Equal(Plain, await a.DecryptAsync(pub.Encrypt(Plain, RSAEncryptionPadding.OaepSHA256)));
    }
}
