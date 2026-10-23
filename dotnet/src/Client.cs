// Read secrets from a SoloSecretsManager server inside CI jobs (SDK-01, SEC-MACH-02).
//
// The server only returns ciphertext. The job proves who it is with a GitHub Actions OIDC token, gets the
// environment key wrapped under SSM_CI_KEY, and decrypts in memory. Nothing is written to disk (SDK-06).
//
//   var pw = await Client.FromEnv().GetAsync("DATABASE_PASSWORD");
//
// Pure port of the decrypt subset with .NET's crypto (SDK-02), checked against testvectors/machine-v1.json.

using System.Buffers.Binary;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SoloSecretsManager.Sdk;

public sealed class SSMException : Exception
{
    public SSMException(string message, Exception? inner = null) : base("ssm: " + message, inner) { }
}

/// <summary>
/// Caches one environment's secrets in memory for the TTL (SDK-04); a revoked grant stops at the next refresh.
/// ponytail: .NET strings can't be wiped; SDK-06 only forbids disk.
/// </summary>
public sealed class Client
{
    private const int Header = 3 + 1 + 1 + 16 + 12;
    private readonly string _host, _serverId, _pin, _environmentId, _ciKey;
    private readonly int _port;
    private readonly TimeSpan _ttl;
    private readonly Func<string, Task<string>> _credential;
    private readonly string _kind;
    private readonly ICloudBackend? _cloud;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private HashSet<string>? _pins;
    private Dictionary<string, string>? _secrets;
    private DateTime _fetched;

    /// <summary>
    /// kind is "github" or "gitlab" for the CI-key kinds; cloud (Cloud.Aws, Cloud.Azure or Cloud.Gcp) replaces the CI key for
    /// cloud workloads (SEC-MACH-06/08/09), and ciKey is then unused.
    /// </summary>
    public Client(string? url, string? serverId, string? pin, string? environmentId, string? ciKey,
                  TimeSpan? ttl = null, Func<string, Task<string>>? credential = null, string kind = "github", ICloudBackend? cloud = null)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != "https") throw new SSMException("URL must be https://host[:port]");
        if (string.IsNullOrEmpty(serverId) || string.IsNullOrEmpty(pin)) throw new SSMException("server ID and pin are required");
        Uuid(environmentId);
        if (kind is not ("github" or "gitlab")) throw new SSMException("kind must be github or gitlab");
        if (cloud is null && B64(ciKey ?? "").Length != 48) throw new SSMException("SSM_CI_KEY is missing or malformed");
        (_kind, _cloud) = (kind, cloud);
        (_host, _port) = (u.IdnHost, u.Port);
        (_serverId, _pin, _environmentId, _ciKey) = (serverId, pin, environmentId!, ciKey ?? "");
        _ttl = ttl ?? TimeSpan.FromMinutes(5);
        _credential = credential ?? (kind == "gitlab" ? GitLabTokenAsync : GitHubTokenAsync);
    }

    /// <summary>
    /// Reads SSM_URL, SSM_SERVER_ID, SSM_PIN, SSM_ENVIRONMENT_ID and SSM_CI_KEY; for cloud workloads SSM_AWS_KMS_KEY, SSM_AZURE_KEY
    /// (+ SSM_AZURE_AUDIENCE) or SSM_GCP_KMS_KEY instead of SSM_CI_KEY (SDK-09).
    /// </summary>
    public static Client FromEnv() => new(Environment.GetEnvironmentVariable("SSM_URL"), Environment.GetEnvironmentVariable("SSM_SERVER_ID"),
        Environment.GetEnvironmentVariable("SSM_PIN"), Environment.GetEnvironmentVariable("SSM_ENVIRONMENT_ID"), Environment.GetEnvironmentVariable("SSM_CI_KEY"),
        kind: Environment.GetEnvironmentVariable("GITLAB_CI") == "true" ? "gitlab" : "github", cloud: Cloud.FromEnv());

    /// <summary>The job's ID token, declared with the server ID as audience: <c>id_tokens: SSM_ID_TOKEN: aud: &lt;server ID&gt;</c>.</summary>
    public static Task<string> GitLabTokenAsync(string audience) =>
        Environment.GetEnvironmentVariable("SSM_ID_TOKEN") is { Length: > 0 } t ? Task.FromResult(t)
            : throw new SSMException("SSM_ID_TOKEN is not set; declare it under id_tokens with the server ID as aud");

    /// <summary>What a cloud KMS decrypted: environment ID ‖ key ID ‖ key; it must be this environment's (SEC-MACH-06/08/09).</summary>
    internal static (byte[] Id, byte[] Key) CloudEnvKey(byte[] plain, string environmentId)
    {
        if (plain.Length != 64 || !plain.AsSpan(0, 16).SequenceEqual(Uuid(environmentId))) throw new SSMException("KMS returned a key for another environment");
        var r = (plain[16..32], plain[32..]);
        CryptographicOperations.ZeroMemory(plain);
        return r;
    }

    public async Task<string> GetAsync(string name)
    {
        var all = await AllAsync();
        return all.TryGetValue(name, out var v) ? v : throw new SSMException($"no secret named \"{name}\" in this environment");
    }

    public async Task<Dictionary<string, string>> AllAsync()
    {
        await _lock.WaitAsync();
        try
        {
            if (_secrets is null || DateTime.UtcNow - _fetched >= _ttl) await RefreshAsync();
            return new Dictionary<string, string>(_secrets!);
        }
        finally { _lock.Release(); }
    }

    private static byte[] B64(string s)
    {
        s = s.Trim().TrimEnd('=').Replace('-', '+').Replace('_', '/');
        try { return Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4)); }
        catch (FormatException e) { throw new SSMException("malformed base64", e); }
    }

    private static string B64E(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Uuid(string? s) =>
        Guid.TryParse(s, out var g) ? g.ToByteArray(bigEndian: true) : throw new SSMException("bad UUID");

    // | magic "SSM" | fmt_ver u8 | alg_id u8 | key_id 16B | nonce 12B | ciphertext … | tag 16B |
    // AAD = fmt_ver ‖ alg_id ‖ key_id ‖ object_id ‖ object_revision (u64 big-endian)
    internal static byte[] Open(byte[] keyId, byte[] key, byte[] obj, ulong revision, byte[] env)
    {
        if (env.Length < Header + 16 || env[0] != 'S' || env[1] != 'S' || env[2] != 'M') throw new SSMException("malformed envelope");
        if (env[3] != 1 || env[4] != 1) throw new SSMException("unsupported envelope version or algorithm");
        if (!env.AsSpan(5, 16).SequenceEqual(keyId)) throw new SSMException("envelope sealed under a different key");
        var aad = new byte[42];
        aad[0] = aad[1] = 1;
        keyId.CopyTo(aad, 2);
        obj.CopyTo(aad, 18);
        BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(34), revision);
        var plain = new byte[env.Length - Header - 16];
        try
        {
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(env.AsSpan(21, 12), env.AsSpan(Header, plain.Length), env.AsSpan(env.Length - 16), plain, aad);
        }
        catch (CryptographicException e) { throw new SSMException("decryption failed (tampered, swapped or wrong key)", e); }
        return plain;
    }

    private static (byte[] Id, byte[] Key) Unwrap(byte[] keyId, byte[] key, byte[] obj, byte[] env)
    {
        var p = Open(keyId, key, obj, 0, env);
        if (p.Length != 48) throw new SSMException("malformed wrapped key");
        var r = (p[..16], p[16..]);
        CryptographicOperations.ZeroMemory(p);
        return r;
    }

    /// <summary>Opens the environment key with the CI key, then each item (SEC-MACH-05). Any failure fails the whole call.</summary>
    internal static Dictionary<string, string> DecryptExchange(string ciKey, string environmentId, JsonNode exchange)
    {
        var raw = B64(ciKey);
        if (raw.Length != 48) throw new SSMException("SSM_CI_KEY is missing or malformed");
        try
        {
            return DecryptItems(Unwrap(raw[..16], raw[16..], Uuid(environmentId), B64((string)exchange["wrapped_key"]!)), exchange);
        }
        catch (Exception e) when (e is InvalidOperationException or NullReferenceException or JsonException or FormatException)
        {
            throw new SSMException("malformed exchange", e);
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    internal static Dictionary<string, string> DecryptItems((byte[] Id, byte[] Key) ek, JsonNode exchange)
    {
        try
        {
            var outp = new Dictionary<string, string>();
            foreach (var it in exchange["items"]!.AsArray())
            {
                var id = Uuid((string?)it!["id"]);
                var ik = Unwrap(ek.Id, ek.Key, id, B64((string)it["item_key"]!));
                var plain = Open(ik.Id, ik.Key, id, (ulong)it["revision"]!, B64((string)it["payload"]!));
                CryptographicOperations.ZeroMemory(ik.Key);
                var p = JsonNode.Parse(plain)!;
                CryptographicOperations.ZeroMemory(plain);
                var name = (string?)p["name"] ?? "";
                if (!outp.TryAdd(name, (string?)p["secret"] ?? "")) throw new SSMException($"two secrets are named \"{name}\"; rename one in the app");
            }
            return outp;
        }
        catch (Exception e) when (e is InvalidOperationException or NullReferenceException or JsonException or FormatException)
        {
            throw new SSMException("malformed exchange", e);
        }
        finally { CryptographicOperations.ZeroMemory(ek.Key); }
    }

    internal static string SpkiPin(byte[] spki) => B64E(SHA256.HashData(spki));

    /// <summary>SEC-TLS-05: the identity key matches pin, signed the statement for this server, and attests connPin.</summary>
    internal static HashSet<string> VerifyAttestation(JsonNode a, string pin, string serverId, string connPin)
    {
        byte[] der, body, sig;
        using var key = ECDsa.Create();
        try
        {
            (der, body, sig) = (B64((string)a["identity_public_key"]!), B64((string)a["statement"]!), B64((string)a["signature"]!));
            key.ImportSubjectPublicKeyInfo(der, out _);
        }
        catch (Exception e) when (e is CryptographicException or InvalidOperationException or NullReferenceException or SSMException)
        {
            throw new SSMException("malformed attestation", e);
        }
        if (SpkiPin(der) != pin || !key.VerifyData(body, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
            throw new SSMException("server identity does not match the pin");
        var st = JsonNode.Parse(body);
        if ((string?)st?["purpose"] != "ssm-tls-attestation-v1" || (string?)st?["server_id"] != serverId)
            throw new SSMException("attestation is not for this server");
        var pins = st!["tls_pins"]?.AsArray().Select(p => (string?)p ?? "").ToHashSet() ?? [];
        if (!pins.Contains(connPin)) throw new SSMException("TLS certificate is not attested by the server identity");
        return pins;
    }

    /// <summary>One request on a fresh TLS 1.3 connection; the handshake fails unless the certificate's pin is attested.</summary>
    private async Task<(int Status, byte[] Body, string? ConnPin)> RequestAsync(HttpMethod method, string path, byte[]? body)
    {
        string? seen = null;
        var allowed = _pins;
        using var handler = new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.Zero,
            SslOptions = new SslClientAuthenticationOptions
            {
                // TLS version: the OS default; the server enforces its minimum (TLS 1.3 unless the owner allows 1.2).
                // ponytail: .NET on macOS has no TLS 1.3 client, so it only reaches servers that allow 1.2 there.
                // Replaces CA and host name checks with the pin check.
                RemoteCertificateValidationCallback = (_, cert, _, _) =>
                {
                    if (cert is null) return false;
                    using var c = new X509Certificate2(cert);
                    seen = SpkiPin(c.PublicKey.ExportSubjectPublicKeyInfo());
                    return allowed is null || allowed.Contains(seen);
                },
            },
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        var host = _host.Contains(':') ? $"[{_host}]" : _host;
        using var req = new HttpRequestMessage(method, $"https://{host}:{_port}{path}");
        if (body is not null) req.Content = new ByteArrayContent(body) { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } };
        using var resp = await http.SendAsync(req);
        return ((int)resp.StatusCode, await resp.Content.ReadAsByteArrayAsync(), seen);
    }

    private async Task RefreshAsync()
    {
        try
        {
            if (_pins is null)
            {
                var r = await RequestAsync(HttpMethod.Get, "/v1/tls/attestation", null);
                if (r.Status != 200) throw new SSMException("server has no valid TLS attestation");
                _pins = VerifyAttestation(JsonNode.Parse(r.Body)!, _pin, _serverId, r.ConnPin!);
            }
            var kind = _cloud?.Kind ?? _kind;
            var cred = _cloud is not null ? await _cloud.IdentityAsync(_serverId) : await _credential(_serverId);
            var req = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, string> { ["environment_id"] = _environmentId, ["kind"] = kind, ["credential"] = cred });
            (int Status, byte[] Body, string? ConnPin) ex;
            try { ex = await RequestAsync(HttpMethod.Post, "/v1/machine/exchange", req); }
            catch (HttpRequestException)
            {
                _pins = null; // the certificate may have rotated: attest again next time
                throw;
            }
            if (ex.Status != 200) throw new SSMException($"server refused this machine identity ({ex.Status})");
            var exchange = JsonNode.Parse(ex.Body)!;
            _secrets = _cloud is not null
                ? DecryptItems(CloudEnvKey(await _cloud.DecryptAsync(B64((string)exchange["wrapped_key"]!)), _environmentId), exchange)
                : DecryptExchange(_ciKey, _environmentId, exchange);
            _fetched = DateTime.UtcNow;
        }
        catch (Exception e) when (e is not SSMException)
        {
            throw new SSMException(e.Message, e);
        }
    }

    /// <summary>Asks the GitHub Actions runner for an OIDC token. The workflow needs <c>permissions: id-token: write</c>.</summary>
    public static async Task<string> GitHubTokenAsync(string audience)
    {
        var url = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL");
        var tok = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(tok))
            throw new SSMException("not in GitHub Actions, or the workflow lacks `permissions: id-token: write`");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        using var req = new HttpRequestMessage(HttpMethod.Get, url + "&audience=" + Uri.EscapeDataString(audience));
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tok);
        using var resp = await http.SendAsync(req);
        var v = resp.IsSuccessStatusCode ? (string?)JsonNode.Parse(await resp.Content.ReadAsStringAsync())?["value"] : null;
        return string.IsNullOrEmpty(v) ? throw new SSMException("GitHub did not issue an OIDC token") : v;
    }
}
