# SoloSecretsManager Python SDK

Reads one environment's secrets from your SSM server inside GitHub Actions. The server only returns
ciphertext; decryption happens in memory with `SSM_CI_KEY` (SEC-MACH-02/05, SDK-08). Apache-2.0.
Configuration, workflow permissions and caching are the same as the Go SDK: see [../go/README.md](../go/README.md).

```python
from solosecretsmanager import Client
password = Client.from_env().get("DATABASE_PASSWORD")
```
