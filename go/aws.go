package ssm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// cloudBackend proves a cloud workload's identity and has its KMS decrypt the environment key (SEC-MACH-06/08/09).
type cloudBackend interface {
	kind() string
	identity(ctx context.Context, serverID string) (string, error)
	decrypt(ctx context.Context, blob []byte) ([]byte, error)
}

type realAWS struct {
	keyARN, sts string
	cfg         aws.Config
	kms         *kms.Client
}

const stsBody = "Action=GetCallerIdentity&Version=2011-06-15"

func newAWS(keyARN, stsEndpoint string) (cloudBackend, error) {
	if stsEndpoint == "" {
		stsEndpoint = "https://sts.amazonaws.com"
	}
	var opts []func(*config.LoadOptions) error
	if p := strings.Split(keyARN, ":"); len(p) >= 4 && p[3] != "" {
		opts = append(opts, config.WithRegion(p[3])) // the key ARN names its region
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}
	return &realAWS{keyARN: keyARN, sts: strings.TrimRight(stsEndpoint, "/"), cfg: cfg, kms: kms.NewFromConfig(cfg)}, nil
}

// identity signs sts:GetCallerIdentity, including x-ssm-server-id so the proof only works on this server, and
// returns it as the exchange credential. Nothing is sent to AWS here; the SSM server forwards it to STS.
func (a *realAWS) identity(ctx context.Context, serverID string) (string, error) {
	creds, err := a.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", err
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", a.sts+"/", strings.NewReader(stsBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Ssm-Server-Id", serverID)
	sum := sha256.Sum256([]byte(stsBody))
	region := "us-east-1" // the global endpoint signs for us-east-1
	if p := strings.Split(strings.TrimPrefix(a.sts, "https://"), "."); len(p) == 4 && p[0] == "sts" {
		region = p[1] // sts.<region>.amazonaws.com
	}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "sts", region, time.Now()); err != nil {
		return "", err
	}
	h := map[string]string{}
	for k := range req.Header {
		h[k] = req.Header.Get(k)
	}
	b, _ := json.Marshal(map[string]any{"method": "POST", "url": a.sts + "/", "headers": h, "body": stsBody})
	return b64.EncodeToString(b), nil
}

func (a *realAWS) kind() string { return "aws" }

func (a *realAWS) decrypt(ctx context.Context, blob []byte) ([]byte, error) {
	out, err := a.kms.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(a.keyARN), CiphertextBlob: blob,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256})
	if err != nil {
		return nil, errors.New("ssm: KMS refused to decrypt the environment key: " + err.Error())
	}
	return out.Plaintext, nil
}
