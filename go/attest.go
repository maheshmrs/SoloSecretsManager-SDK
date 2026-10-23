package ssm

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
)

var b64 = base64.RawURLEncoding

// spkiPin is base64url(SHA-256(DER SubjectPublicKeyInfo)), as the server and apps compute it (SEC-TLS-01).
func spkiPin(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return b64.EncodeToString(h[:])
}

type attestation struct {
	IdentityPublicKey string `json:"identity_public_key"`
	Statement         string `json:"statement"`
	Signature         string `json:"signature"`
}

// attest fetches GET /v1/tls/attestation on a fresh connection and returns the TLS pins the server's identity
// key vouches for (SEC-TLS-05). The identity key must match pin, the statement must name serverID, and the
// certificate on that same connection must be among the attested pins.
func attest(ctx context.Context, base *url.URL, pin, serverID string) (map[string]bool, error) {
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, ServerName: base.Hostname()}}
	host := base.Host
	if base.Port() == "" {
		host = net.JoinHostPort(base.Hostname(), "443")
	}
	c, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	tc := c.(*tls.Conn)
	connPin := spkiPin(tc.ConnectionState().PeerCertificates[0])
	req, _ := http.NewRequestWithContext(ctx, "GET", base.JoinPath("/v1/tls/attestation").String(), nil)
	req.Close = true
	if err := req.Write(c); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var a attestation
	if resp.StatusCode != 200 || json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64<<10)).Decode(&a) != nil {
		return nil, errors.New("ssm: server has no valid TLS attestation")
	}
	return verifyAttestation(a, pin, serverID, connPin)
}

// verifyAttestation checks the identity key against pin, its signature, the purpose and server ID, and that connPin
// is attested; it returns the attested pins (contract: testvectors/machine-v1.json).
func verifyAttestation(a attestation, pin, serverID, connPin string) (map[string]bool, error) {
	der, e1 := b64.DecodeString(a.IdentityPublicKey)
	body, e2 := b64.DecodeString(a.Statement)
	sig, e3 := b64.DecodeString(a.Signature)
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, errors.New("ssm: malformed attestation")
	}
	h := sha256.Sum256(der)
	pub, err := x509.ParsePKIXPublicKey(der)
	ec, ok := pub.(*ecdsa.PublicKey)
	sum := sha256.Sum256(body)
	if err != nil || !ok || b64.EncodeToString(h[:]) != pin || !ecdsa.VerifyASN1(ec, sum[:], sig) {
		return nil, errors.New("ssm: server identity does not match the pin")
	}
	var st struct {
		Purpose  string   `json:"purpose"`
		ServerID string   `json:"server_id"`
		TLSPins  []string `json:"tls_pins"`
	}
	if json.Unmarshal(body, &st) != nil || st.Purpose != "ssm-tls-attestation-v1" || st.ServerID != serverID {
		return nil, errors.New("ssm: attestation is not for this server")
	}
	pins := map[string]bool{}
	for _, p := range st.TLSPins {
		pins[p] = true
	}
	if !pins[connPin] {
		return nil, errors.New("ssm: TLS certificate is not attested by the server identity")
	}
	return pins, nil
}
