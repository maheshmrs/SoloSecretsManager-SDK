# SoloSecretsManager Go SDK

Reads one environment's secrets from your SSM server inside GitHub Actions. The server only returns
ciphertext; decryption happens in memory with `SSM_CI_KEY` (SEC-MACH-02/05). Apache-2.0.

```go
c, err := ssm.FromEnv()
pw, err := c.Get(ctx, "DATABASE_PASSWORD")
```

Workflow:

```yaml
permissions:
  id-token: write   # lets the job ask GitHub for an OIDC token
  contents: read
env:
  SSM_URL: https://vault.example.com:8443
  SSM_SERVER_ID: vault.example.com
  SSM_PIN: <server pin from the app>
  SSM_ENVIRONMENT_ID: <from the app's grant screen>
  SSM_CI_KEY: ${{ secrets.SSM_CI_KEY }}
```

Secrets are cached in memory for 5 minutes (`Config.TTL`); a revoked grant stops working at the next refresh.

## Who can read (SEC-MACH-05..09, SDK-09)

Every SDK supports the same five kinds and picks one from the environment:

| Kind | Set | Proof of identity | Second lock |
|---|---|---|---|
| GitHub Actions | `SSM_CI_KEY` | GitHub OIDC token (`permissions: id-token: write`) | CI key in repository secrets |
| GitLab CI | `SSM_CI_KEY`, `id_tokens: SSM_ID_TOKEN: aud: <server ID>` | GitLab ID token | CI key in a masked, protected variable |
| AWS | `SSM_AWS_KMS_KEY` (key ARN) | signed `sts:GetCallerIdentity` bound to the server ID | KMS RSA key only the role can decrypt with |
| Azure | `SSM_AZURE_KEY` (Key Vault key URL), `SSM_AZURE_AUDIENCE` | managed identity token for the registered audience | Key Vault RSA key only the identity can decrypt with |
| GCP | `SSM_GCP_KMS_KEY` (key version name) | Google ID token for the server ID | Cloud KMS RSA key only the service account can decrypt with |

The app's Settings → CI and cloud access screen creates the grant and shows the exact settings. AWS credentials come
from the environment, web identity (EKS IRSA), container credentials (ECS, EKS Pod Identity) or EC2 IMDSv2; the Go SDK
also reads AWS profiles.
