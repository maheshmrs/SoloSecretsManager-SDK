package ssm

// Pure-Go, decrypt-only port of ssm-core-read (SDK-03), cross-checked against ssm-core with
// testvectors/machine-v1.json (QA-G-03).
//
// | magic "SSM" | fmt_ver u8 | alg_id u8 | key_id 16B | nonce 12B | ciphertext … | tag 16B |
// AAD = fmt_ver ‖ alg_id ‖ key_id ‖ object_id ‖ object_revision (u64 big-endian)

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	fmtV1      = 1
	algAES256  = 1
	headerLen  = 3 + 1 + 1 + 16 + 12
	tagLen     = 16
	wrappedLen = 48 // key ID ‖ key bytes
)

var (
	errMalformed = errors.New("ssm: malformed envelope")
	errWrongKey  = errors.New("ssm: envelope sealed under a different key")
	errDecrypt   = errors.New("ssm: decryption failed (tampered, swapped or wrong key)")
)

// key is a symmetric key and its 16-byte ID.
type key struct {
	id    [16]byte
	bytes [32]byte
}

func (k *key) wipe() { k.bytes = [32]byte{} }

func open(k *key, objID [16]byte, revision uint64, env []byte) ([]byte, error) {
	if len(env) < headerLen+tagLen || string(env[:3]) != "SSM" {
		return nil, errMalformed
	}
	if env[3] != fmtV1 || env[4] != algAES256 {
		return nil, errors.New("ssm: unsupported envelope version or algorithm")
	}
	if [16]byte(env[5:21]) != k.id {
		return nil, errWrongKey
	}
	aad := make([]byte, 42)
	aad[0], aad[1] = fmtV1, algAES256
	copy(aad[2:18], k.id[:])
	copy(aad[18:34], objID[:])
	binary.BigEndian.PutUint64(aad[34:], revision)
	block, _ := aes.NewCipher(k.bytes[:])
	gcm, _ := cipher.NewGCM(block)
	out, err := gcm.Open(nil, env[21:33], env[headerLen:], aad)
	if err != nil {
		return nil, errDecrypt
	}
	return out, nil
}

func unwrapKey(k *key, objID [16]byte, env []byte) (*key, error) {
	plain, err := open(k, objID, 0, env)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if len(plain) != wrappedLen {
		return nil, errMalformed
	}
	return &key{id: [16]byte(plain[:16]), bytes: [32]byte(plain[16:])}, nil
}
