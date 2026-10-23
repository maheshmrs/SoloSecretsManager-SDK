package ssm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type contractCase struct {
	Name          string          `json:"name"`
	CIKey         string          `json:"ci_key"`
	EnvironmentID string          `json:"environment_id"`
	Exchange      json.RawMessage `json:"exchange"`
}

type attestCase struct {
	Name        string      `json:"name"`
	Pin         string      `json:"pin"`
	ServerID    string      `json:"server_id"`
	ConnPin     string      `json:"conn_pin"`
	Attestation attestation `json:"attestation"`
	Pins        []string    `json:"pins"`
}

type vectors struct {
	contractCase
	Expected          map[string]string `json:"expected"`
	Reject            []contractCase    `json:"reject"`
	Attestation       attestCase        `json:"attestation"`
	AttestationReject []attestCase      `json:"attestation_reject"`
}

func load(t *testing.T) (vectors, exchangeResponse) {
	b, err := os.ReadFile("../testvectors/machine-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	var ex exchangeResponse
	if json.Unmarshal(b, &v) != nil || json.Unmarshal(v.Exchange, &ex) != nil {
		t.Fatal("bad vectors file")
	}
	return v, ex
}

func open1(c contractCase) (map[string]string, error) {
	cl, err := New(Config{URL: "https://x", ServerID: "s", Pin: "p", EnvironmentID: c.EnvironmentID, CIKey: c.CIKey})
	if err != nil {
		return nil, err
	}
	var ex exchangeResponse
	if err := json.Unmarshal(c.Exchange, &ex); err != nil {
		return nil, err
	}
	return decryptExchange(&cl.ci, cl.env, ex)
}

// QA-G-03: the shared machine contract written by ssm-core.
func TestContract(t *testing.T) {
	v, _ := load(t)
	got, err := open1(v.contractCase)
	if err != nil || len(got) != len(v.Expected) {
		t.Fatalf("accept: %v %v", got, err)
	}
	for k, want := range v.Expected {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
	for _, r := range v.Reject {
		if _, err := open1(r); err == nil {
			t.Errorf("reject %q: accepted", r.Name)
		}
	}
	a := v.Attestation
	pins, err := verifyAttestation(a.Attestation, a.Pin, a.ServerID, a.ConnPin)
	if err != nil || len(pins) != len(a.Pins) {
		t.Fatalf("attestation: %v %v", pins, err)
	}
	for _, p := range a.Pins {
		if !pins[p] {
			t.Errorf("pin %s missing", p)
		}
	}
	for _, r := range v.AttestationReject {
		if _, err := verifyAttestation(r.Attestation, r.Pin, r.ServerID, r.ConnPin); err == nil {
			t.Errorf("attestation reject %q: accepted", r.Name)
		}
	}
}

// fakeServer serves a signed TLS attestation and the vectors' exchange response.
func fakeServer(t *testing.T, serverID string, attestOwnCert bool) (srv *httptest.Server, pin string, calls *atomic.Int32) {
	v, _ := load(t)
	id, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&id.PublicKey)
	h := sha256.Sum256(der)
	pin = b64.EncodeToString(h[:])
	calls = &atomic.Int32{}
	mux := http.NewServeMux()
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	certPin := spkiPin(srv.Certificate())
	if !attestOwnCert {
		certPin = "someone-else"
	}
	mux.HandleFunc("GET /v1/tls/attestation", func(w http.ResponseWriter, _ *http.Request) {
		body, _ := json.Marshal(map[string]any{"purpose": "ssm-tls-attestation-v1", "server_id": serverID, "tls_pins": []string{certPin}})
		sum := sha256.Sum256(body)
		sig, _ := ecdsa.SignASN1(rand.Reader, id, sum[:])
		json.NewEncoder(w).Encode(attestation{b64.EncodeToString(der), b64.EncodeToString(body), b64.EncodeToString(sig)})
	})
	mux.HandleFunc("POST /v1/machine/exchange", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		if req["credential"] != "jwt-for-"+serverID || req["environment_id"] != v.EnvironmentID || req["kind"] != "github" {
			w.WriteHeader(401)
			return
		}
		w.Write(v.Exchange)
	})
	return srv, pin, calls
}

func TestClientEndToEnd(t *testing.T) {
	v, _ := load(t)
	srv, pin, calls := fakeServer(t, "vault.test", true)
	cred := func(_ context.Context, aud string) (string, error) { return "jwt-for-" + aud, nil }
	c, err := New(Config{URL: srv.URL, ServerID: "vault.test", Pin: pin, EnvironmentID: v.EnvironmentID, CIKey: v.CIKey,
		Credential: cred, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, err := c.Get(ctx, "DATABASE_PASSWORD"); err != nil || got != "hunter2" {
		t.Fatalf("get: %q %v", got, err)
	}
	if _, err := c.Get(ctx, "NOPE"); err == nil || !strings.Contains(err.Error(), "NOPE") {
		t.Fatal("missing name", err)
	}
	if calls.Load() != 1 {
		t.Fatal("cache not used, exchanges:", calls.Load())
	}

	for name, cfg := range map[string]Config{
		"wrong pin":       {URL: srv.URL, ServerID: "vault.test", Pin: "AAAA"},
		"wrong server ID": {URL: srv.URL, ServerID: "other", Pin: pin},
	} {
		cfg.EnvironmentID, cfg.CIKey, cfg.Credential = v.EnvironmentID, v.CIKey, cred
		c, _ := New(cfg)
		if _, err := c.Get(ctx, "DATABASE_PASSWORD"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad, pin2, _ := fakeServer(t, "vault.test", false)
	c2, _ := New(Config{URL: bad.URL, ServerID: "vault.test", Pin: pin2, EnvironmentID: v.EnvironmentID, CIKey: v.CIKey, Credential: cred})
	if _, err := c2.Get(ctx, "DATABASE_PASSWORD"); err == nil {
		t.Error("unattested certificate accepted")
	}
	if _, err := New(Config{URL: "http://x", ServerID: "s", Pin: "p", EnvironmentID: v.EnvironmentID, CIKey: v.CIKey}); err == nil {
		t.Error("plain http accepted")
	}
}
