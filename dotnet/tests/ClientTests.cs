// QA-G-03 contract plus an end-to-end run against a fake TLS server.
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using SoloSecretsManager.Sdk;

public class ClientTests
{
    static readonly JsonNode V = JsonNode.Parse(File.ReadAllText(Path.Combine(Root(), "testvectors/machine-v1.json")))!;

    static string Root()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (!Directory.Exists(Path.Combine(d!.FullName, "testvectors"))) d = d.Parent;
        return d.FullName;
    }

    [Fact]
    public void ContractAccept()
    {
        var got = Client.DecryptExchange((string)V["ci_key"]!, (string)V["environment_id"]!, V["exchange"]!);
        var want = V["expected"]!.AsObject().ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
        Assert.Equal(want, got);
    }

    [Fact]
    public void ContractReject()
    {
        var rejects = V["reject"]!.AsArray();
        Assert.True(rejects.Count >= 10);
        foreach (var r in rejects)
        {
            var e = Record.Exception(() => Client.DecryptExchange((string)r!["ci_key"]!, (string)r["environment_id"]!, r["exchange"]!));
            Assert.True(e is SSMException, $"{r!["name"]}: {e?.GetType().Name ?? "accepted"}");
        }
    }

    [Fact]
    public void ContractAttestation()
    {
        var a = V["attestation"]!;
        Assert.Equal(a["pins"]!.AsArray().Select(p => (string)p!).ToHashSet(),
            Client.VerifyAttestation(a["attestation"]!, (string)a["pin"]!, (string)a["server_id"]!, (string)a["conn_pin"]!));
        foreach (var r in V["attestation_reject"]!.AsArray())
        {
            var e = Record.Exception(() => Client.VerifyAttestation(r!["attestation"]!, (string)r["pin"]!, (string)r["server_id"]!, (string)r["conn_pin"]!));
            Assert.True(e is SSMException, $"{r!["name"]}: {e?.GetType().Name ?? "accepted"}");
        }
    }

    static string B64E(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    sealed class Fake : IDisposable
    {
        readonly TcpListener _l = new(IPAddress.Loopback, 0);
        readonly CancellationTokenSource _cts = new();
        public string Url => $"https://127.0.0.1:{((IPEndPoint)_l.LocalEndpoint).Port}";
        public string Pin;
        public int Calls;

        public Fake(string serverId, bool attestOwnCert)
        {
            using var tlsKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=localhost", tlsKey, HashAlgorithmName.SHA256);
            using var tmp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
            var cert = X509CertificateLoader.LoadPkcs12(tmp.Export(X509ContentType.Pfx), null);
            var certPin = attestOwnCert ? B64E(SHA256.HashData(cert.PublicKey.ExportSubjectPublicKeyInfo())) : "someone-else";
            using var id = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var der = id.ExportSubjectPublicKeyInfo();
            Pin = B64E(SHA256.HashData(der));
            var body = Encoding.UTF8.GetBytes(new JsonObject { ["purpose"] = "ssm-tls-attestation-v1", ["server_id"] = serverId, ["tls_pins"] = new JsonArray(certPin) }.ToJsonString());
            var attestation = new JsonObject { ["identity_public_key"] = B64E(der), ["statement"] = B64E(body),
                ["signature"] = B64E(id.SignData(body, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)) }.ToJsonString();
            var exchange = V["exchange"]!.ToJsonString();
            _l.Start();
            _ = Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    var c = await _l.AcceptTcpClientAsync(_cts.Token);
                    _ = Task.Run(async () =>
                    {
                        using var _c = c;
                        using var ssl = new SslStream(c.GetStream());
                        try { await ssl.AuthenticateAsServerAsync(cert); } catch { return; }
                        var (line, reqBody) = await ReadRequest(ssl);
                        string resp;
                        int status = 200;
                        if (line.StartsWith("GET /v1/tls/attestation")) resp = attestation;
                        else
                        {
                            Interlocked.Increment(ref Calls);
                            var r = JsonNode.Parse(reqBody)!;
                            var ok = (string?)r["environment_id"] == (string?)V["environment_id"] && (string?)r["kind"] == "github" && (string?)r["credential"] == "jwt-for-" + serverId;
                            (status, resp) = ok ? (200, exchange) : (401, "");
                        }
                        var bytes = Encoding.UTF8.GetBytes(resp);
                        await ssl.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status} X\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n"));
                        await ssl.WriteAsync(bytes);
                    });
                }
            });
        }

        static async Task<(string, string)> ReadRequest(Stream s)
        {
            var buf = new List<byte>();
            var one = new byte[1];
            while (!(buf.Count >= 4 && buf[^4] == '\r' && buf[^3] == '\n' && buf[^2] == '\r' && buf[^1] == '\n'))
            {
                if (await s.ReadAsync(one) == 0) break;
                buf.Add(one[0]);
            }
            var head = Encoding.ASCII.GetString(buf.ToArray());
            var len = head.Split("\r\n").Where(h => h.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)).Select(h => int.Parse(h[15..].Trim())).FirstOrDefault();
            var body = new byte[len];
            await s.ReadExactlyAsync(body);
            return (head.Split("\r\n")[0], Encoding.UTF8.GetString(body));
        }

        public void Dispose() { _cts.Cancel(); _l.Stop(); }
    }

    [Fact]
    public async Task EndToEnd()
    {
        Func<string, Task<string>> cred = aud => Task.FromResult("jwt-for-" + aud);
        string env = (string)V["environment_id"]!, ci = (string)V["ci_key"]!;
        using var s = new Fake("vault.test", true);
        using var bad = new Fake("vault.test", false);
        var c = new Client(s.Url, "vault.test", s.Pin, env, ci, TimeSpan.FromHours(1), cred);
        Assert.Equal("hunter2", await c.GetAsync("DATABASE_PASSWORD"));
        await Assert.ThrowsAsync<SSMException>(() => c.GetAsync("NOPE"));
        Assert.Equal(1, s.Calls); // cached
        foreach (var (sid, pin) in new[] { ("vault.test", "AAAA"), ("other", s.Pin) })
            await Assert.ThrowsAsync<SSMException>(() => new Client(s.Url, sid, pin, env, ci, null, cred).GetAsync("DATABASE_PASSWORD"));
        await Assert.ThrowsAsync<SSMException>(() => new Client(bad.Url, "vault.test", bad.Pin, env, ci, null, cred).GetAsync("DATABASE_PASSWORD"));
        Assert.Throws<SSMException>(() => new Client("http://x", "s", "p", env, ci));
    }
}
