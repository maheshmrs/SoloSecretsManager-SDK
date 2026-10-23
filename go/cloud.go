package ssm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var metaClient = &http.Client{Timeout: 10 * time.Second}

// getJSON sends one request and decodes a JSON answer, or returns the body as text when out is a *string.
func getJSON(ctx context.Context, method, u string, hdr map[string]string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := metaClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %s %s", method, strings.SplitN(u, "?", 2)[0], resp.Status, strings.TrimSpace(string(data)))
	}
	if s, ok := out.(*string); ok {
		*s = strings.TrimSpace(string(data))
		return nil
	}
	return json.Unmarshal(data, out)
}

// ---------- Azure managed identity + Key Vault (SEC-MACH-08) ----------

type azure struct {
	keyURL, audience string
	imds             string // overridable in tests
}

func newAzure(keyURL, audience string) (cloudBackend, error) {
	u, err := url.Parse(keyURL)
	if err != nil || u.Scheme != "https" || !strings.Contains(u.Path, "/keys/") {
		return nil, errors.New("ssm: SSM_AZURE_KEY must be a Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>/<version>)")
	}
	if audience == "" {
		return nil, errors.New("ssm: SSM_AZURE_AUDIENCE is required (the application ID URI registered for the server)")
	}
	return &azure{keyURL: strings.TrimRight(keyURL, "/"), audience: audience, imds: "http://169.254.169.254"}, nil
}

func (a *azure) kind() string { return "azure" }

// token gets a managed identity token for resource: App Service / Functions (IDENTITY_ENDPOINT) or IMDS (VMs, AKS
// with pod-managed identity). ponytail: AKS workload identity (federated token file) is not handled yet.
func (a *azure) token(ctx context.Context, resource string) (string, error) {
	var out struct {
		AccessToken string `json:"access_token"`
	}
	var err error
	if ep, h := os.Getenv("IDENTITY_ENDPOINT"), os.Getenv("IDENTITY_HEADER"); ep != "" && h != "" {
		err = getJSON(ctx, "GET", ep+"?api-version=2019-08-01&resource="+url.QueryEscape(resource), map[string]string{"X-IDENTITY-HEADER": h}, nil, &out)
	} else {
		err = getJSON(ctx, "GET", a.imds+"/metadata/identity/oauth2/token?api-version=2018-02-01&resource="+url.QueryEscape(resource),
			map[string]string{"Metadata": "true"}, nil, &out)
	}
	if err == nil && out.AccessToken == "" {
		err = errors.New("no access token")
	}
	if err != nil {
		return "", errors.New("ssm: Azure managed identity: " + err.Error())
	}
	return out.AccessToken, nil
}

func (a *azure) identity(ctx context.Context, _ string) (string, error) {
	return a.token(ctx, a.audience)
}

func (a *azure) decrypt(ctx context.Context, blob []byte) ([]byte, error) {
	tok, err := a.token(ctx, "https://vault.azure.net")
	if err != nil {
		return nil, err
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := getJSON(ctx, "POST", a.keyURL+"/decrypt?api-version=7.4", map[string]string{"Authorization": "Bearer " + tok},
		map[string]string{"alg": "RSA-OAEP-256", "value": b64.EncodeToString(blob)}, &out); err != nil {
		return nil, errors.New("ssm: Key Vault refused to decrypt the environment key: " + err.Error())
	}
	return b64.DecodeString(strings.TrimRight(out.Value, "="))
}

// ---------- GCP service account + Cloud KMS (SEC-MACH-09) ----------

type gcp struct {
	keyVersion   string
	metadata, km string // overridable in tests
}

func newGCP(keyVersion string) (cloudBackend, error) {
	if !strings.HasPrefix(keyVersion, "projects/") || !strings.Contains(keyVersion, "/cryptoKeyVersions/") {
		return nil, errors.New("ssm: SSM_GCP_KMS_KEY must be a key version name (projects/…/cryptoKeys/…/cryptoKeyVersions/N)")
	}
	return &gcp{keyVersion: keyVersion, metadata: "http://metadata.google.internal", km: "https://cloudkms.googleapis.com"}, nil
}

func (g *gcp) kind() string { return "gcp" }

const gcpSA = "/computeMetadata/v1/instance/service-accounts/default/"

// identity gets a Google-signed ID token for the server ID, including the service account's email (format=full).
func (g *gcp) identity(ctx context.Context, serverID string) (string, error) {
	var tok string
	if err := getJSON(ctx, "GET", g.metadata+gcpSA+"identity?format=full&audience="+url.QueryEscape(serverID),
		map[string]string{"Metadata-Flavor": "Google"}, nil, &tok); err != nil {
		return "", errors.New("ssm: GCP metadata server: " + err.Error())
	}
	return tok, nil
}

func (g *gcp) decrypt(ctx context.Context, blob []byte) ([]byte, error) {
	var at struct {
		AccessToken string `json:"access_token"`
	}
	if err := getJSON(ctx, "GET", g.metadata+gcpSA+"token", map[string]string{"Metadata-Flavor": "Google"}, nil, &at); err != nil {
		return nil, errors.New("ssm: GCP metadata server: " + err.Error())
	}
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	if err := getJSON(ctx, "POST", g.km+"/v1/"+g.keyVersion+":asymmetricDecrypt", map[string]string{"Authorization": "Bearer " + at.AccessToken},
		map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(blob)}, &out); err != nil {
		return nil, errors.New("ssm: Cloud KMS refused to decrypt the environment key: " + err.Error())
	}
	return base64.StdEncoding.DecodeString(out.Plaintext)
}
