package ssm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// SDK-09: AWS's own Go signer writes testvectors/aws-sigv4.json; the hand-written SigV4 in every other SDK must
// produce exactly these headers. Regenerate with SSM_WRITE_VECTORS=1 go test -run TestSigV4Vectors.
func TestSigV4Vectors(t *testing.T) {
	const path = "../testvectors/aws-sigv4.json"
	if os.Getenv("SSM_WRITE_VECTORS") == "" {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
		return
	}
	creds := aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", SessionToken: "session-token-example"}
	at := time.Date(2026, 10, 16, 1, 2, 3, 0, time.UTC)
	type tc struct {
		Name    string            `json:"name"`
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Region  string            `json:"region"`
		Service string            `json:"service"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
		Signed  map[string]string `json:"signed"` // headers the signer adds
	}
	cases := []tc{
		{Name: "sts GetCallerIdentity bound to the server", Method: "POST", URL: "https://sts.amazonaws.com/", Region: "us-east-1", Service: "sts",
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "X-Ssm-Server-Id": "vault.example.com"},
			Body:    stsBody},
		{Name: "kms Decrypt", Method: "POST", URL: "https://kms.eu-west-1.amazonaws.com/", Region: "eu-west-1", Service: "kms",
			Headers: map[string]string{"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "TrentService.Decrypt"},
			Body:    `{"KeyId":"arn:aws:kms:eu-west-1:111122223333:key/k","CiphertextBlob":"AAEC","EncryptionAlgorithm":"RSAES_OAEP_SHA_256"}`},
	}
	for i, c := range cases {
		req, _ := http.NewRequest(c.Method, c.URL, strings.NewReader(c.Body))
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}
		sum := sha256.Sum256([]byte(c.Body))
		if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, hex.EncodeToString(sum[:]), c.Service, c.Region, at); err != nil {
			t.Fatal(err)
		}
		cases[i].Signed = map[string]string{}
		for _, k := range []string{"Authorization", "X-Amz-Date", "X-Amz-Security-Token"} {
			cases[i].Signed[k] = req.Header.Get(k)
		}
	}
	out, _ := json.MarshalIndent(map[string]any{"access_key_id": creds.AccessKeyID, "secret_access_key": creds.SecretAccessKey,
		"session_token": creds.SessionToken, "time": at.Format(time.RFC3339), "cases": cases}, "", "  ")
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
