# SoloSecretsManager Rust SDK

Reads one environment's secrets from your SSM server inside GitHub Actions. The server only returns ciphertext;
decryption happens in memory with `SSM_CI_KEY` through `ssm-core-read` (SEC-MACH-02/05, SDK-02/08). Apache-2.0.
Configuration, workflow permissions and caching are the same as the Go SDK: see [../go/README.md](../go/README.md).

```rust
let mut c = solosecretsmanager::Client::from_env()?;
let password = c.get("DATABASE_PASSWORD")?;
```
