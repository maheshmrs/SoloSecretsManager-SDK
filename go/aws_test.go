package ssm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type fakeAWS struct{ k *rsa.PrivateKey }

func (f fakeAWS) kind() string                                     { return "aws" }
func (f fakeAWS) identity(context.Context, string) (string, error) { return "proof", nil }
func (f fakeAWS) decrypt(_ context.Context, blob []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), nil, f.k, blob, nil)
}

// wrapForAWS does what the app does (SEC-MACH-06): RSA-OAEP-SHA256 of environment ID ‖ key ID ‖ key.
func wrapForAWS(t *testing.T, pub *rsa.PublicKey, env [16]byte, k *key) string {
	plain := append(append(env[:], k.id[:]...), k.bytes[:]...)
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(ct)
}

func TestAWSEnvironmentKey(t *testing.T) {
	v, ex := load(t)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	c, err := New(Config{URL: "https://x", ServerID: "s", Pin: "p", EnvironmentID: v.EnvironmentID, AWSKMSKey: "arn:aws:kms:us-east-1:1:key/k", cloud: fakeAWS{rk}})
	if err != nil {
		t.Fatal(err)
	}
	ci, _ := New(Config{URL: "https://x", ServerID: "s", Pin: "p", EnvironmentID: v.EnvironmentID, CIKey: v.CIKey})
	envKey, err := ci.ciEnvKey(ex.WrappedKey) // the real environment key, from the contract
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.cloudEnvKey(context.Background(), wrapForAWS(t, &rk.PublicKey, c.env, envKey))
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptItems(k, ex)
	if err != nil || got["DATABASE_PASSWORD"] != "hunter2" {
		t.Fatalf("%v %v", got, err)
	}
	other := c.env
	other[0] ^= 1
	if _, err := c.cloudEnvKey(context.Background(), wrapForAWS(t, &rk.PublicKey, other, envKey)); err == nil {
		t.Fatal("key for another environment accepted")
	}
}

// With floci running (SSM_TEST_FLOCI=1; https://floci.io), the real AWS code signs a proof STS accepts and KMS
// decrypts what the app wrapped. Real AWS also rejects bad signatures; floci doesn't check them.
func TestAWSAgainstFloci(t *testing.T) {
	if os.Getenv("SSM_TEST_FLOCI") == "" {
		t.Skip("set SSM_TEST_FLOCI=1 with floci running")
	}
	const ep = "http://localhost:4566"
	t.Setenv("AWS_ENDPOINT_URL", ep)
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	awsCLI := func(args ...string) string {
		out, err := exec.Command("aws", append([]string{"--endpoint-url", ep, "--output", "text"}, args...)...).Output()
		if err != nil {
			t.Fatal(args, err)
		}
		return strings.TrimSpace(string(out))
	}
	keyARN := awsCLI("kms", "create-key", "--key-spec", "RSA_2048", "--key-usage", "ENCRYPT_DECRYPT", "--query", "KeyMetadata.Arn")
	der, _ := base64.StdEncoding.DecodeString(awsCLI("kms", "get-public-key", "--key-id", keyARN, "--query", "PublicKey"))
	role := fmt.Sprintf("ssm-sdk-test-%d", time.Now().UnixNano())
	awsCLI("iam", "create-role", "--role-name", role, "--assume-role-policy-document", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`)
	f := strings.Fields(awsCLI("sts", "assume-role", "--role-arn", "arn:aws:iam::000000000000:role/"+role, "--role-session-name", "ci", "--query", "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]"))
	t.Setenv("AWS_ACCESS_KEY_ID", f[0])
	t.Setenv("AWS_SECRET_ACCESS_KEY", f[1])
	t.Setenv("AWS_SESSION_TOKEN", f[2])

	a, err := newAWS(keyARN, ep)
	if err != nil {
		t.Fatal(err)
	}
	// The SSM server forwards the proof to STS; do the same here and read the caller.
	cred, err := a.identity(context.Background(), "vault.test")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := b64.DecodeString(cred)
	var p struct {
		Headers map[string]string
		Body    string
	}
	json.Unmarshal(raw, &p)
	if !strings.Contains(p.Headers["Authorization"], "x-ssm-server-id") || p.Headers["X-Ssm-Server-Id"] != "vault.test" {
		t.Fatal("server ID not signed:", p.Headers)
	}
	req, _ := http.NewRequest("POST", ep+"/", strings.NewReader(p.Body))
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		Arn string `xml:"GetCallerIdentityResult>Arn"`
	}
	xml.Unmarshal(body, &out)
	if out.Arn != "arn:aws:sts::000000000000:assumed-role/"+role+"/ci" {
		t.Fatalf("STS said %s: %s", resp.Status, body)
	}

	pub, err := parseRSA(der)
	if err != nil {
		t.Fatal(err)
	}
	env, k := [16]byte{1, 2, 3}, &key{id: [16]byte{9}, bytes: [32]byte{7}}
	blob, _ := b64.DecodeString(wrapForAWS(t, pub, env, k))
	plain, err := a.decrypt(context.Background(), blob)
	if err != nil || !bytes.Equal(plain[:16], env[:]) || [32]byte(plain[32:]) != k.bytes {
		t.Fatalf("KMS decrypt: %v", err)
	}
}

func parseRSA(der []byte) (*rsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	return k.(*rsa.PublicKey), nil
}
