// Package ssm reads secrets from a SoloSecretsManager server inside CI jobs (SDK-01, SEC-MACH-02).
//
// The server only ever returns ciphertext. The job proves who it is with a GitHub Actions OIDC token, gets the
// environment key wrapped under SSM_CI_KEY, and decrypts in memory. Nothing is written to disk (SDK-06).
//
//	c, err := ssm.FromEnv()
//	pw, err := c.Get(ctx, "DATABASE_PASSWORD")
package ssm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Config says which server and environment to read, and how to prove identity.
type Config struct {
	URL           string // https://vault.example.com:8443
	ServerID      string // the server ID the apps pin; also the OIDC audience
	Pin           string // server identity pin (base64url SHA-256 of its SPKI)
	EnvironmentID string // UUID of the project environment
	CIKey         string // SSM_CI_KEY, shown once by the app when access was granted
	// TTL is how long fetched secrets are reused before the next exchange (SDK-04). Default 5 minutes.
	// A revoked grant stops working at the next refresh.
	TTL time.Duration
	// Credential returns a GitHub Actions OIDC token for audience. Default: GitHubToken.
	Credential func(ctx context.Context, audience string) (string, error)

	// AWS workload identity (SEC-MACH-06) instead of GitHub: the KMS key ARN the app wrapped the environment key
	// to (SSM_AWS_KMS_KEY). CIKey is then unused. AWS credentials come from the default AWS chain.
	AWSKMSKey string
	// STS endpoint the identity proof is signed for; must match the server's. Default https://sts.amazonaws.com.
	AWSSTSEndpoint string

	// Azure managed identity (SEC-MACH-08): the Key Vault key URL (SSM_AZURE_KEY) and the audience the owner
	// registered for the server (SSM_AZURE_AUDIENCE).
	AzureKey, AzureAudience string
	// GCP service account (SEC-MACH-09): the Cloud KMS key version name (SSM_GCP_KMS_KEY).
	GCPKMSKey string

	// Kind is "github" (default) or "gitlab" for the CI-key kinds; cloud kinds follow from the settings above.
	// In GitLab CI the default Credential reads the job's ID token from SSM_ID_TOKEN.
	Kind string

	cloud cloudBackend // tests replace the cloud calls
}

// Client caches one environment's secrets in memory.
type Client struct {
	cfg     Config
	base    *url.URL
	env     [16]byte
	ci      key
	http    *http.Client
	mu      sync.Mutex
	pins    map[string]bool
	secrets map[string]string
	fetched time.Time
}

// FromEnv reads SSM_URL, SSM_SERVER_ID, SSM_PIN, SSM_ENVIRONMENT_ID and SSM_CI_KEY, or for AWS workloads
// SSM_AWS_KMS_KEY (and optionally SSM_AWS_STS_ENDPOINT) instead of SSM_CI_KEY.
func FromEnv() (*Client, error) {
	return New(Config{URL: os.Getenv("SSM_URL"), ServerID: os.Getenv("SSM_SERVER_ID"), Pin: os.Getenv("SSM_PIN"),
		EnvironmentID: os.Getenv("SSM_ENVIRONMENT_ID"), CIKey: os.Getenv("SSM_CI_KEY"),
		AWSKMSKey: os.Getenv("SSM_AWS_KMS_KEY"), AWSSTSEndpoint: os.Getenv("SSM_AWS_STS_ENDPOINT"),
		AzureKey: os.Getenv("SSM_AZURE_KEY"), AzureAudience: os.Getenv("SSM_AZURE_AUDIENCE"), GCPKMSKey: os.Getenv("SSM_GCP_KMS_KEY"),
		Kind: map[bool]string{true: "gitlab"}[os.Getenv("GITLAB_CI") == "true"]})
}

func New(cfg Config) (*Client, error) {
	base, err := url.Parse(cfg.URL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, errors.New("ssm: URL must be https://host[:port]")
	}
	if cfg.ServerID == "" || cfg.Pin == "" {
		return nil, errors.New("ssm: server ID and pin are required")
	}
	env, err := hex.DecodeString(strings.ReplaceAll(cfg.EnvironmentID, "-", ""))
	if err != nil || len(env) != 16 {
		return nil, errors.New("ssm: environment ID must be a UUID")
	}
	if cfg.cloud == nil {
		switch {
		case cfg.AWSKMSKey != "":
			cfg.cloud, err = newAWS(cfg.AWSKMSKey, cfg.AWSSTSEndpoint)
		case cfg.AzureKey != "":
			cfg.cloud, err = newAzure(cfg.AzureKey, cfg.AzureAudience)
		case cfg.GCPKMSKey != "":
			cfg.cloud, err = newGCP(cfg.GCPKMSKey)
		}
		if err != nil {
			return nil, err
		}
	}
	if cfg.Kind == "" {
		cfg.Kind = "github"
	}
	if cfg.Kind != "github" && cfg.Kind != "gitlab" {
		return nil, errors.New("ssm: Kind must be github or gitlab")
	}
	raw, err := b64.DecodeString(strings.TrimRight(strings.TrimSpace(cfg.CIKey), "="))
	if cfg.cloud != nil {
		raw, err = make([]byte, wrappedLen), nil // no CI key for cloud workloads
	}
	if err != nil || len(raw) != wrappedLen {
		return nil, errors.New("ssm: SSM_CI_KEY is missing or malformed")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.Credential == nil {
		cfg.Credential = GitHubToken
		if cfg.Kind == "gitlab" {
			cfg.Credential = GitLabToken
		}
	}
	c := &Client{cfg: cfg, base: base, env: [16]byte(env), ci: key{id: [16]byte(raw[:16]), bytes: [32]byte(raw[16:])}}
	clear(raw)
	// Every connection must present a certificate the server's identity key attested (SEC-TLS-05).
	c.http = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // replaced by the pin check below
		MinVersion:         tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			c.mu.Lock()
			ok := c.pins[spkiPin(cs.PeerCertificates[0])]
			c.mu.Unlock()
			if !ok {
				return errors.New("ssm: server certificate is not pinned")
			}
			return nil
		},
	}}}
	return c, nil
}

// Get returns one secret by item name.
func (c *Client) Get(ctx context.Context, name string) (string, error) {
	all, err := c.All(ctx)
	if err != nil {
		return "", err
	}
	v, ok := all[name]
	if !ok {
		return "", fmt.Errorf("ssm: no secret named %q in this environment", name)
	}
	return v, nil
}

// All returns every secret in the environment, keyed by item name. The map is a copy.
func (c *Client) All(ctx context.Context) (map[string]string, error) {
	c.mu.Lock()
	fresh := c.secrets != nil && time.Since(c.fetched) < c.cfg.TTL
	c.mu.Unlock()
	if !fresh {
		if err := c.refresh(ctx); err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]string, len(c.secrets))
	for k, v := range c.secrets {
		out[k] = v
	}
	return out, nil
}

type exchangeResponse struct {
	WrappedKey string `json:"wrapped_key"`
	Items      []struct {
		ID       string `json:"id"`
		ItemKey  string `json:"item_key"`
		Payload  string `json:"payload"`
		Revision uint64 `json:"revision"`
	} `json:"items"`
}

func (c *Client) refresh(ctx context.Context) error {
	c.mu.Lock()
	needPins := c.pins == nil
	c.mu.Unlock()
	if needPins {
		pins, err := attest(ctx, c.base, c.cfg.Pin, c.cfg.ServerID)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.pins = pins
		c.mu.Unlock()
	}
	kind, cred := c.cfg.Kind, ""
	var err error
	if c.cfg.cloud != nil {
		kind = c.cfg.cloud.kind()
		cred, err = c.cfg.cloud.identity(ctx, c.cfg.ServerID)
	} else {
		cred, err = c.cfg.Credential(ctx, c.cfg.ServerID)
	}
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"environment_id": uuidString(c.env), "kind": kind, "credential": cred})
	req, _ := http.NewRequestWithContext(ctx, "POST", c.base.JoinPath("/v1/machine/exchange").String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		c.mu.Lock()
		c.pins = nil // the certificate may have rotated: attest again next time
		c.mu.Unlock()
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("ssm: server refused this machine identity (%s)", resp.Status)
	}
	var ex exchangeResponse
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64<<20)).Decode(&ex); err != nil {
		return err
	}
	var envKey *key
	if c.cfg.cloud != nil {
		envKey, err = c.cloudEnvKey(ctx, ex.WrappedKey)
	} else {
		envKey, err = c.ciEnvKey(ex.WrappedKey)
	}
	if err != nil {
		return err
	}
	secrets, err := decryptItems(envKey, ex)
	envKey.wipe()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.secrets, c.fetched = secrets, time.Now()
	c.mu.Unlock()
	return nil
}

// decryptExchange opens the environment key with the CI key, then each item (SSM-SPEC-03 §10, SEC-MACH-05).
// Any item that fails to open fails the whole call: a wrong value must never be returned.
//
// ponytail: Go strings can't be wiped; secrets live in the heap until GC. Acceptable for CI jobs (SDK-06 only
// forbids disk), revisit with []byte accessors if a long-lived service needs it.
func decryptExchange(ci *key, env [16]byte, ex exchangeResponse) (map[string]string, error) {
	c := &Client{env: env, ci: *ci}
	envKey, err := c.ciEnvKey(ex.WrappedKey)
	if err != nil {
		return nil, err
	}
	defer envKey.wipe()
	return decryptItems(envKey, ex)
}

// ciEnvKey opens the environment key with SSM_CI_KEY (SEC-MACH-05).
func (c *Client) ciEnvKey(wrapped string) (*key, error) {
	wk, err := b64.DecodeString(strings.TrimRight(wrapped, "="))
	if err != nil {
		return nil, errMalformed
	}
	return unwrapKey(&c.ci, c.env, wk)
}

// cloudEnvKey has the cloud KMS decrypt environment ID ‖ key ID ‖ key and checks it is this environment's
// (SEC-MACH-06/08/09).
func (c *Client) cloudEnvKey(ctx context.Context, wrapped string) (*key, error) {
	wk, err := b64.DecodeString(strings.TrimRight(wrapped, "="))
	if err != nil {
		return nil, errMalformed
	}
	plain, err := c.cfg.cloud.decrypt(ctx, wk)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if len(plain) != 64 || [16]byte(plain[:16]) != c.env {
		return nil, errors.New("ssm: KMS returned a key for another environment")
	}
	return &key{id: [16]byte(plain[16:32]), bytes: [32]byte(plain[32:])}, nil
}

func decryptItems(envKey *key, ex exchangeResponse) (map[string]string, error) {
	out := map[string]string{}
	for _, it := range ex.Items {
		id, err := hex.DecodeString(strings.ReplaceAll(it.ID, "-", ""))
		ik, err1 := b64.DecodeString(strings.TrimRight(it.ItemKey, "="))
		pl, err2 := b64.DecodeString(strings.TrimRight(it.Payload, "="))
		if err != nil || err1 != nil || err2 != nil || len(id) != 16 {
			return nil, errMalformed
		}
		itemKey, err := unwrapKey(envKey, [16]byte(id), ik)
		if err != nil {
			return nil, err
		}
		plain, err := open(itemKey, [16]byte(id), it.Revision, pl)
		itemKey.wipe()
		if err != nil {
			return nil, err
		}
		var p struct {
			Name   string `json:"name"`
			Secret string `json:"secret"`
		}
		err = json.Unmarshal(plain, &p)
		clear(plain)
		if err != nil {
			return nil, errMalformed
		}
		if _, dup := out[p.Name]; dup {
			return nil, fmt.Errorf("ssm: two secrets are named %q; rename one in the app", p.Name)
		}
		out[p.Name] = p.Secret
	}
	return out, nil
}

func uuidString(u [16]byte) string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// GitLabToken returns the job's ID token. The job declares it with the server ID as audience:
//
//	id_tokens:
//	  SSM_ID_TOKEN:
//	    aud: <server ID>
func GitLabToken(context.Context, string) (string, error) {
	if t := os.Getenv("SSM_ID_TOKEN"); t != "" {
		return t, nil
	}
	return "", errors.New("ssm: SSM_ID_TOKEN is not set; declare it under id_tokens with the server ID as aud")
}

// GitHubToken asks the GitHub Actions runner for an OIDC token. The workflow needs `permissions: id-token: write`.
func GitHubToken(ctx context.Context, audience string) (string, error) {
	u, tok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if u == "" || tok == "" {
		return "", errors.New("ssm: not in GitHub Actions, or the workflow lacks `permissions: id-token: write`")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", u+"&audience="+url.QueryEscape(audience), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var v struct{ Value string }
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&v) != nil || v.Value == "" {
		return "", errors.New("ssm: GitHub did not issue an OIDC token")
	}
	return v.Value, nil
}
