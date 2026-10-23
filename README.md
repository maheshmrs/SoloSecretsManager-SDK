# SoloSecretsManager SDKs

Read secrets from your [SoloSecretsManager](https://solosecretsmanager.com) server in CI jobs and cloud workloads.
The server only ever returns ciphertext; it is decrypted in memory inside your job. Apache-2.0.

| Language | Folder | Read a secret |
|---|---|---|
| Python | [python](python) | `Client.from_env().get("DATABASE_PASSWORD")` |
| Node | [node](node) | `await Client.fromEnv().get("DATABASE_PASSWORD")` |
| Go | [go](go) | `c, _ := ssm.FromEnv(); c.Get(ctx, "DATABASE_PASSWORD")` |
| Java / Kotlin | [java](java) | `Client.fromEnv().get("DATABASE_PASSWORD")` |
| .NET | [dotnet](dotnet) | `await Client.FromEnv().GetAsync("DATABASE_PASSWORD")` |
| Rust | [rust](rust) | `Client::from_env()?.get("DATABASE_PASSWORD")?` |

Every SDK reads the same settings from environment variables and signs in from GitHub Actions, GitLab CI, AWS, Azure
or GCP. In the app, open **Settings → CI and cloud access** to create a grant; it shows exactly what to set. See
[go/README.md](go/README.md) for the full list, and the [developer help](https://solosecretsmanager.com/help/developers)
for step-by-step examples.

Other folders:

- `ssm-core-read`: the Rust decrypt subset the Rust SDK uses.
- `testvectors`: shared test vectors every SDK's tests check against (generated keys, not real secrets).

Run each SDK's tests from its folder (`go test ./...`, `node --test`, `python -m unittest discover -s tests`,
`cargo test`, `./gradlew test`, `dotnet test tests`).

Security issues: support@aidigiapps.com.
