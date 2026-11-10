//! Key hierarchy.
//!
//! ```text
//! device secret (32 random bytes, stays on the machine, ideally TPM-sealed)
//!   ├─ HKDF "auth"            → Ed25519 key that signs every request (server stores the public half)
//!   ├─ HKDF "oprf-input"/sid  → x_i, the OPRF input for key server i (never leaves the machine)
//!   └─ salt for the share-wrap keys below
//!
//! OPRF output  N_i = F(k_i, x_i)          (k_i lives only on key server i)
//!   └─ HKDF(salt = device secret) → wrap key that encrypts Shamir share i of the master key
//!
//! volume master key (32 random bytes, exists only transiently in RAM)
//!   ├─ HKDF "volume-passphrase" → the LUKS passphrase
//!   └─ HKDF "key-check"         → value stored locally to detect a wrong reconstruction
//! ```

use crate::encoding::{b64, Transcript};
use crate::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceSecret([u8; 32]);

impl DeviceSecret {
    pub fn generate() -> Self {
        DeviceSecret(random_bytes())
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        DeviceSecret(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn signing_key(&self) -> SigningKey {
        let seed = Zeroizing::new(hkdf32(b"zknbe/v1", &self.0, b"auth"));
        SigningKey::from_bytes(&seed)
    }

    pub fn auth_public(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key().sign(msg).to_bytes()
    }

    /// The OPRF input for one key server. Distinct per server so servers cannot correlate.
    pub fn oprf_input(&self, server_id: &str) -> Zeroizing<[u8; 32]> {
        let info = Transcript::new("oprf-input").str(server_id).finish();
        Zeroizing::new(hkdf32(b"zknbe/v1", &self.0, &info))
    }

    /// Key that encrypts this device's Shamir share held against server `server_id`.
    /// Needs both the server's contribution (the OPRF output) and the device secret.
    pub fn share_wrap_key(
        &self,
        oprf_output: &[u8; 64],
        device_id: &str,
        server_id: &str,
        epoch: u64,
    ) -> Zeroizing<[u8; 32]> {
        let info = Transcript::new("share-wrap")
            .str(device_id)
            .str(server_id)
            .u64(epoch)
            .finish();
        Zeroizing::new(hkdf32(&self.0, oprf_output, &info))
    }
}

pub fn share_aad(device_id: &str, server_id: &str, epoch: u64, index: u8) -> Vec<u8> {
    Transcript::new("share-aad")
        .str(device_id)
        .str(server_id)
        .u64(epoch)
        .u64(index as u64)
        .finish()
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn generate() -> Self {
        MasterKey(random_bytes())
    }

    pub fn from_slice(b: &[u8]) -> Result<Self> {
        Ok(MasterKey(b.try_into().map_err(|_| {
            Error::Encoding("master key must be 32 bytes")
        })?))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The passphrase enrolled in the LUKS keyslot: 256 bits, base64url, no newline.
    pub fn passphrase(&self, device_id: &str) -> Zeroizing<String> {
        let info = Transcript::new("volume-passphrase").str(device_id).finish();
        let raw = Zeroizing::new(hkdf32(b"zknbe/v1", &self.0, &info));
        Zeroizing::new(b64(&raw[..]))
    }

    pub fn check_value(&self, device_id: &str) -> String {
        let info = Transcript::new("key-check").str(device_id).finish();
        b64(&hkdf32(b"zknbe/v1", &self.0, &info)[..16])
    }

    pub fn matches(&self, device_id: &str, check: &str) -> bool {
        self.check_value(device_id)
            .as_bytes()
            .ct_eq(check.as_bytes())
            .into()
    }
}

pub fn verify_signature(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| Error::BadSignature)?;
    let sig = Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
    key.verify_strict(msg, &sig)
        .map_err(|_| Error::BadSignature)
}

/// A long-term Ed25519 identity (used by key servers to sign responses).
pub struct Identity(SigningKey);

impl Identity {
    pub fn generate() -> Self {
        Identity(SigningKey::from_bytes(
            &Zeroizing::new(random_bytes::<32>()),
        ))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Identity(SigningKey::from_bytes(seed))
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

/// HMAC-SHA256 keyed from an enrolment-token secret; authenticates enrolment in both
/// directions so that enrolment is safe even over an untrusted transport.
pub fn enroll_mac(token_secret: &[u8], msg: &[u8]) -> [u8; 32] {
    let key = Zeroizing::new(hkdf32(b"zknbe/v1", token_secret, b"enroll-mac"));
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[..]).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

pub fn verify_enroll_mac(token_secret: &[u8], msg: &[u8], tag: &[u8]) -> Result<()> {
    if bool::from(enroll_mac(token_secret, msg).ct_eq(tag)) {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivations_are_stable_and_separated() {
        let d = DeviceSecret::from_bytes([1u8; 32]);
        assert_eq!(
            d.auth_public(),
            DeviceSecret::from_bytes([1u8; 32]).auth_public()
        );
        assert_ne!(*d.oprf_input("a"), *d.oprf_input("b"));
        let out = [5u8; 64];
        assert_ne!(
            *d.share_wrap_key(&out, "dev", "srv", 1),
            *d.share_wrap_key(&out, "dev", "srv", 2)
        );
        assert_ne!(
            *d.share_wrap_key(&out, "dev", "srv", 1),
            *DeviceSecret::from_bytes([2u8; 32]).share_wrap_key(&out, "dev", "srv", 1)
        );
    }

    #[test]
    fn signatures() {
        let d = DeviceSecret::generate();
        let sig = d.sign(b"msg");
        verify_signature(&d.auth_public(), b"msg", &sig).unwrap();
        assert!(verify_signature(&d.auth_public(), b"msh", &sig).is_err());
        assert!(verify_signature(&d.auth_public(), b"msg", &sig[..63]).is_err());
    }

    #[test]
    fn master_key_outputs() {
        let m = MasterKey::from_slice(&[3u8; 32]).unwrap();
        assert_eq!(m.passphrase("d").len(), 43);
        assert!(m.matches("d", &m.check_value("d")));
        assert!(!m.matches("e", &m.check_value("d")));
        assert_ne!(*m.passphrase("d"), *m.passphrase("e"));
    }

    #[test]
    fn enroll_mac_verifies() {
        let tag = enroll_mac(b"secret", b"msg");
        verify_enroll_mac(b"secret", b"msg", &tag).unwrap();
        assert!(verify_enroll_mac(b"secreT", b"msg", &tag).is_err());
    }
}
