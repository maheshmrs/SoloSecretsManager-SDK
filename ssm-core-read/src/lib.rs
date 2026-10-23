//! SoloSecretsManager decrypt subset (LIC-02): the versioned ciphertext envelope (DM-05)
//! and the crypto backend trait (SEC-IMPL-04). Apache-2.0, so SDKs can link it.
//! Apache-2.0: must not depend on the proprietary crates.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Too short, or bad magic.
    Malformed,
    UnsupportedVersion(u8),
    UnsupportedAlgorithm(u8),
    /// Envelope was sealed under a different key ID.
    WrongKey,
    /// Authentication failed: tampered, swapped, replayed or wrong key bytes.
    Decrypt,
    Random,
}

/// All cryptographic primitives go through this trait (SEC-IMPL-04), so FIPS mode can
/// swap in an OS-validated module (SEC-FIPS-01, PH-07).
pub trait CryptoBackend {
    fn random(&self, buf: &mut [u8]) -> Result<(), Error>;
    /// Returns ciphertext followed by the 16-byte tag.
    fn aes256gcm_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error>;
    fn aes256gcm_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error>;
}

/// Standard profile backend (SEC-IMPL-01).
pub struct RustCrypto;

impl CryptoBackend for RustCrypto {
    fn random(&self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf).map_err(|_| Error::Random)
    }

    fn aes256gcm_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Aes256Gcm::new(key.into())
            .encrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Decrypt)
    }

    fn aes256gcm_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        Aes256Gcm::new(key.into())
            .decrypt(&Nonce::from(*nonce), Payload { msg: sealed, aad })
            .map(Zeroizing::new)
            .map_err(|_| Error::Decrypt)
    }
}

/// A symmetric key and its 16-byte key ID. Key bytes are wiped on drop.
pub struct Key {
    pub id: [u8; 16],
    bytes: Zeroizing<[u8; 32]>,
}

impl Key {
    pub fn new(id: [u8; 16], bytes: [u8; 32]) -> Self {
        Key {
            id,
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn generate(backend: &impl CryptoBackend) -> Result<Self, Error> {
        let mut id = [0u8; 16];
        let mut bytes = Zeroizing::new([0u8; 32]);
        backend.random(&mut id)?;
        backend.random(bytes.as_mut())?;
        Ok(Key { id, bytes })
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// The object a ciphertext belongs to. Bound as AAD so the server cannot swap
/// ciphertexts between objects or replay an old revision (STRIDE "Tampering", QA-SEC-02).
#[derive(Clone, Copy)]
pub struct ObjectRef {
    pub id: [u8; 16],
    pub revision: u64,
}

const MAGIC: &[u8; 3] = b"SSM";
pub const FMT_V1: u8 = 1;
pub const ALG_AES256GCM: u8 = 1;
const HEADER_LEN: usize = 3 + 1 + 1 + 16 + 12;
const TAG_LEN: usize = 16;

// | magic "SSM" | fmt_ver u8 | alg_id u8 | key_id 16B | nonce 12B | ciphertext … | tag 16B |
// AAD = fmt_ver ‖ alg_id ‖ key_id ‖ object_id ‖ object_revision (u64 big-endian)
fn aad(fmt: u8, alg: u8, key_id: &[u8; 16], obj: ObjectRef) -> [u8; 42] {
    let mut a = [0u8; 42];
    a[0] = fmt;
    a[1] = alg;
    a[2..18].copy_from_slice(key_id);
    a[18..34].copy_from_slice(&obj.id);
    a[34..42].copy_from_slice(&obj.revision.to_be_bytes());
    a
}

/// Encrypts `plaintext` for `obj` under `key` into a v1 envelope (DM-05).
pub fn seal(
    backend: &impl CryptoBackend,
    key: &Key,
    obj: ObjectRef,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    // ponytail: random 96-bit nonces; fine for per-item keys, revisit if one key ever seals ~2^32 messages.
    let mut nonce = [0u8; 12];
    backend.random(&mut nonce)?;
    let sealed = backend.aes256gcm_seal(
        key.bytes(),
        &nonce,
        &aad(FMT_V1, ALG_AES256GCM, &key.id, obj),
        plaintext,
    )?;
    let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[FMT_V1, ALG_AES256GCM]);
    out.extend_from_slice(&key.id);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Returns the key ID an envelope was sealed under, so callers can pick the right key.
pub fn key_id(envelope: &[u8]) -> Result<[u8; 16], Error> {
    if envelope.len() < HEADER_LEN + TAG_LEN || &envelope[..3] != MAGIC {
        return Err(Error::Malformed);
    }
    Ok(envelope[5..21].try_into().unwrap())
}

/// Decrypts a v1 envelope. Fails unless key, object ID and revision all match.
pub fn open(
    backend: &impl CryptoBackend,
    key: &Key,
    obj: ObjectRef,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let kid = key_id(envelope)?;
    match envelope[3] {
        FMT_V1 => {}
        v => return Err(Error::UnsupportedVersion(v)),
    }
    match envelope[4] {
        ALG_AES256GCM => {}
        a => return Err(Error::UnsupportedAlgorithm(a)),
    }
    if kid != key.id {
        return Err(Error::WrongKey);
    }
    let nonce: [u8; 12] = envelope[21..33].try_into().unwrap();
    backend.aes256gcm_open(
        key.bytes(),
        &nonce,
        &aad(FMT_V1, ALG_AES256GCM, &kid, obj),
        &envelope[HEADER_LEN..],
    )
}

/// Wraps `inner` (ID + bytes) under `wrapping` for `obj`, e.g. an item key under the vault
/// key, or a project-environment key under a CI-held secret (SEC-MACH-02).
pub fn wrap_key(
    backend: &impl CryptoBackend,
    wrapping: &Key,
    obj: ObjectRef,
    inner: &Key,
) -> Result<Vec<u8>, Error> {
    let mut plain = Zeroizing::new([0u8; 48]);
    plain[..16].copy_from_slice(&inner.id);
    plain[16..].copy_from_slice(inner.bytes());
    seal(backend, wrapping, obj, plain.as_ref())
}

/// Inverse of [`wrap_key`].
pub fn unwrap_key(
    backend: &impl CryptoBackend,
    wrapping: &Key,
    obj: ObjectRef,
    envelope: &[u8],
) -> Result<Key, Error> {
    let plain = open(backend, wrapping, obj, envelope)?;
    if plain.len() != 48 {
        return Err(Error::Malformed);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&plain[16..]);
    Ok(Key {
        id: plain[..16].try_into().unwrap(),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const OBJ: ObjectRef = ObjectRef {
        id: [7; 16],
        revision: 3,
    };

    // QA-G-02: NIST GCM spec, test case 14 (AES-256, zero key/IV/plaintext).
    #[test]
    fn aes256gcm_known_answer() {
        let sealed = RustCrypto
            .aes256gcm_seal(&[0; 32], &[0; 12], &[], &[0; 16])
            .unwrap();
        assert_eq!(
            sealed,
            unhex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
        );
        assert_eq!(
            *RustCrypto
                .aes256gcm_open(&[0; 32], &[0; 12], &[], &sealed)
                .unwrap(),
            vec![0; 16]
        );
    }

    #[test]
    fn round_trip_and_layout() {
        let key = Key::generate(&RustCrypto).unwrap();
        let env = seal(&RustCrypto, &key, OBJ, b"hunter2").unwrap();
        assert_eq!(env.len(), HEADER_LEN + 7 + TAG_LEN);
        assert_eq!(&env[..5], b"SSM\x01\x01");
        assert_eq!(key_id(&env).unwrap(), key.id);
        assert_eq!(&*open(&RustCrypto, &key, OBJ, &env).unwrap(), b"hunter2");
    }

    // QA-SEC-02: swapped, replayed or modified ciphertext must fail.
    #[test]
    fn tampering_is_rejected() {
        let key = Key::generate(&RustCrypto).unwrap();
        let env = seal(&RustCrypto, &key, OBJ, b"secret").unwrap();

        let swapped = ObjectRef { id: [8; 16], ..OBJ };
        assert_eq!(open(&RustCrypto, &key, swapped, &env), Err(Error::Decrypt));

        let replayed = ObjectRef { revision: 4, ..OBJ };
        assert_eq!(open(&RustCrypto, &key, replayed, &env), Err(Error::Decrypt));

        for i in [21, HEADER_LEN, env.len() - 1] {
            let mut bad = env.clone();
            bad[i] ^= 1;
            assert_eq!(
                open(&RustCrypto, &key, OBJ, &bad),
                Err(Error::Decrypt),
                "byte {i}"
            );
        }

        let other = Key::new(key.id, [9; 32]);
        assert_eq!(open(&RustCrypto, &other, OBJ, &env), Err(Error::Decrypt));
    }

    #[test]
    fn header_errors() {
        let key = Key::generate(&RustCrypto).unwrap();
        let env = seal(&RustCrypto, &key, OBJ, b"x").unwrap();
        assert_eq!(
            open(&RustCrypto, &key, OBJ, &env[..HEADER_LEN + TAG_LEN - 1]),
            Err(Error::Malformed)
        );
        let mut bad = env.clone();
        bad[0] = b'X';
        assert_eq!(open(&RustCrypto, &key, OBJ, &bad), Err(Error::Malformed));
        let mut bad = env.clone();
        bad[3] = 2;
        assert_eq!(
            open(&RustCrypto, &key, OBJ, &bad),
            Err(Error::UnsupportedVersion(2))
        );
        let mut bad = env.clone();
        bad[4] = 9;
        assert_eq!(
            open(&RustCrypto, &key, OBJ, &bad),
            Err(Error::UnsupportedAlgorithm(9))
        );
        let wrong = Key::generate(&RustCrypto).unwrap();
        assert_eq!(open(&RustCrypto, &wrong, OBJ, &env), Err(Error::WrongKey));
    }

    #[test]
    fn key_wrap_round_trip() {
        let outer = Key::generate(&RustCrypto).unwrap();
        let inner = Key::generate(&RustCrypto).unwrap();
        let w = wrap_key(&RustCrypto, &outer, OBJ, &inner).unwrap();
        let back = unwrap_key(&RustCrypto, &outer, OBJ, &w).unwrap();
        assert_eq!((back.id, back.bytes()), (inner.id, inner.bytes()));
        let not_a_key = seal(&RustCrypto, &outer, OBJ, b"short").unwrap();
        assert_eq!(
            unwrap_key(&RustCrypto, &outer, OBJ, &not_a_key).err(),
            Some(Error::Malformed)
        );
    }
}
