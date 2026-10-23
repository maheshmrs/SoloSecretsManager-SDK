package ssm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// SEC-MACH-08/09: the Azure and GCP backends ask the right metadata endpoint for the right audience, send the KMS
// the right algorithm, and get back what the app wrapped.
func TestAzureAndGCPBackends(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	plain := []byte("environment-id-key-id-and-key-bytes-sixty-four-bytes-long......")
	blob, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rk.PublicKey, plain, nil)
	rsaDecrypt := func(ct []byte) []byte { p, _ := rsa.DecryptOAEP(sha256.New(), nil, rk, ct, nil); return p }

	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		switch {
		case r.URL.Path == "/metadata/identity/oauth2/token" && r.Header.Get("Metadata") == "true":
			json.NewEncoder(w).Encode(map[string]string{"access_token": "az-" + r.URL.Query().Get("resource")})
		case strings.HasSuffix(r.URL.Path, "/decrypt") && r.Header.Get("Authorization") == "Bearer az-https://vault.azure.net":
			var req struct{ Alg, Value string }
			json.NewDecoder(r.Body).Decode(&req)
			ct, _ := base64.RawURLEncoding.DecodeString(req.Value)
			if req.Alg != "RSA-OAEP-256" {
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"value": base64.RawURLEncoding.EncodeToString(rsaDecrypt(ct))})
		case strings.HasSuffix(r.URL.Path, gcpSA+"identity") && r.Header.Get("Metadata-Flavor") == "Google":
			w.Write([]byte("gcp-id-token-for-" + r.URL.Query().Get("audience") + "-" + r.URL.Query().Get("format")))
		case strings.HasSuffix(r.URL.Path, gcpSA+"token") && r.Header.Get("Metadata-Flavor") == "Google":
			json.NewEncoder(w).Encode(map[string]string{"access_token": "gcp-at"})
		case strings.HasSuffix(r.URL.Path, ":asymmetricDecrypt") && r.Header.Get("Authorization") == "Bearer gcp-at":
			var req struct{ Ciphertext string }
			json.NewDecoder(r.Body).Decode(&req)
			ct, _ := base64.StdEncoding.DecodeString(req.Ciphertext)
			json.NewEncoder(w).Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString(rsaDecrypt(ct))})
		default:
			w.WriteHeader(403)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	az, err := newAzure("https://v.vault.azure.net/keys/ssm/1", "api://ssm-vault")
	if err != nil {
		t.Fatal(err)
	}
	az.(*azure).imds = srv.URL
	az.(*azure).keyURL = srv.URL + "/keys/ssm/1"
	if tok, err := az.identity(ctx, "vault.test"); err != nil || tok != "az-api://ssm-vault" {
		t.Fatalf("azure identity %q %v (must use the registered audience, not the server ID)", tok, err)
	}
	if got, err := az.decrypt(ctx, blob); err != nil || string(got) != string(plain) {
		t.Fatalf("key vault: %v", err)
	}

	g, err := newGCP("projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1")
	if err != nil {
		t.Fatal(err)
	}
	g.(*gcp).metadata, g.(*gcp).km = srv.URL, srv.URL
	if tok, err := g.identity(ctx, "vault.test"); err != nil || tok != "gcp-id-token-for-vault.test-full" {
		t.Fatalf("gcp identity %q %v", tok, err)
	}
	if got, err := g.decrypt(ctx, blob); err != nil || string(got) != string(plain) {
		t.Fatalf("cloud kms: %v", err)
	}
	if !strings.Contains(strings.Join(seen, "\n"), "/v1/projects/p/locations/global/keyRings/r/cryptoKeys/ssm/cryptoKeyVersions/1:asymmetricDecrypt") {
		t.Fatal("wrong KMS path:", seen)
	}

	for _, bad := range []func() error{
		func() error { _, err := newAzure("http://v/keys/k", "a"); return err },
		func() error { _, err := newAzure("https://v.vault.azure.net/keys/k/1", ""); return err },
		func() error { _, err := newGCP("my-key"); return err },
	} {
		if bad() == nil {
			t.Error("bad cloud setting accepted")
		}
	}
	t.Setenv("SSM_ID_TOKEN", "")
	if _, err := GitLabToken(ctx, "s"); err == nil {
		t.Error("GitLab token without SSM_ID_TOKEN")
	}
	t.Setenv("SSM_ID_TOKEN", "glt")
	if tok, _ := GitLabToken(ctx, "s"); tok != "glt" {
		t.Error("GitLab token not read")
	}
}

// With floci az and gcp running (SSM_TEST_FLOCI=1): Key Vault and Cloud KMS decrypt what the app wrapped to their
// public keys, using a real floci managed identity token for Key Vault.
func TestAzureAndGCPAgainstFloci(t *testing.T) {
	if os.Getenv("SSM_TEST_FLOCI") == "" {
		t.Skip("set SSM_TEST_FLOCI=1 with floci az and gcp running")
	}
	ctx := context.Background()
	plain := []byte("environment-id-key-id-and-key-bytes-sixty-four-bytes-long......")

	var k struct{ Key struct{ Kid, N, E string } }
	if err := getJSON(ctx, "POST", "http://localhost:4577/keys/ssm-sdk-test/create?api-version=7.4", map[string]string{"Authorization": "Bearer x"},
		map[string]any{"kty": "RSA", "key_size": 2048, "key_ops": []string{"encrypt", "decrypt"}}, &k); err != nil {
		t.Fatal(err)
	}
	n, _ := base64.RawURLEncoding.DecodeString(k.Key.N)
	e, _ := base64.RawURLEncoding.DecodeString(k.Key.E)
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	blob, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plain, nil)
	az, _ := newAzure(k.Key.Kid, "api://ssm-vault")
	az.(*azure).imds = "http://localhost:4577"
	az.(*azure).keyURL = "http://localhost:4577" + strings.TrimPrefix(k.Key.Kid, "https://kv-default.vault.azure.net")
	if got, err := az.decrypt(ctx, blob); err != nil || string(got) != string(plain) {
		t.Fatalf("Key Vault: %q %v", got, err)
	}

	const ring = "http://localhost:4588/v1/projects/p/locations/global/keyRings/ssm-sdk-test"
	getJSON(ctx, "POST", strings.Replace(ring, "/ssm-sdk-test", "?keyRingId=ssm-sdk-test", 1), nil, map[string]any{}, &map[string]any{})
	getJSON(ctx, "POST", ring+"/cryptoKeys?cryptoKeyId=ssm", nil,
		map[string]any{"purpose": "ASYMMETRIC_DECRYPT", "versionTemplate": map[string]string{"algorithm": "RSA_DECRYPT_OAEP_2048_SHA256"}}, &map[string]any{})
	var pk struct{ Pem string }
	if err := getJSON(ctx, "GET", ring+"/cryptoKeys/ssm/cryptoKeyVersions/1/publicKey", nil, nil, &pk); err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(pk.Pem))
	gpub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, gpub.(*rsa.PublicKey), plain, nil)
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { // floci has no metadata server
		json.NewEncoder(w).Encode(map[string]string{"access_token": "x"})
	}))
	defer meta.Close()
	g, _ := newGCP("projects/p/locations/global/keyRings/ssm-sdk-test/cryptoKeys/ssm/cryptoKeyVersions/1")
	g.(*gcp).metadata, g.(*gcp).km = meta.URL, "http://localhost:4588"
	if got, err := g.decrypt(ctx, blob); err != nil || string(got) != string(plain) {
		t.Fatalf("Cloud KMS: %q %v", got, err)
	}
}
