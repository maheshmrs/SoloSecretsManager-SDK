# SoloSecretsManager .NET SDK

Reads one environment's secrets from your SSM server inside GitHub Actions. The server only returns ciphertext;
decryption happens in memory with `SSM_CI_KEY` (SEC-MACH-02/05, SDK-08). No dependencies. Apache-2.0.
Configuration, workflow permissions and caching are the same as the Go SDK: see [../go/README.md](../go/README.md).

```csharp
var password = await Client.FromEnv().GetAsync("DATABASE_PASSWORD");
```

On macOS, .NET has no TLS 1.3 client, so there it only reaches servers that allow TLS 1.2. Linux and Windows runners are unaffected.
