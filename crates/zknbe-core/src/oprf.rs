//! Verifiable oblivious PRF over ristretto255.
//!
//! `F(k, x) = H2(x, k * H1(x))` – the classic 2HashDH construction, in the shape of
//! RFC 9497's VOPRF mode (the hash-to-group and transcript encodings are our own, so this is
//! *not* wire compatible with RFC 9497 suites).
//!
//! * The client sends `B = r * H1(x)` for a fresh random `r`. `B` is a uniformly random group
//!   element, statistically independent of `x`: the server learns nothing about the input.
//! * The server returns `Z = k * B` and a DLEQ proof that `log_G(Y) == log_B(Z)` where
//!   `Y = k * G` is the public key the client pinned at enrolment. The proof is a
//!   non-interactive zero-knowledge proof (Chaum-Pedersen with Fiat-Shamir): it convinces the
//!   client the right key was used and reveals nothing about `k`.
//! * The client unblinds `N = r^-1 * Z = k * H1(x)` and hashes it together with `x`.
//!   The server never sees `N` or the output.

use crate::{Error, Result};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

const DST_H1: &[u8] = b"zknbe/v1/oprf/hash-to-group";
const DST_H2: &[u8] = b"zknbe/v1/oprf/finalize";
const DST_DLEQ: &[u8] = b"zknbe/v1/oprf/dleq";

pub const ELEMENT_LEN: usize = 32;
pub const SCALAR_LEN: usize = 32;
pub const OUTPUT_LEN: usize = 64;

/// A server-side OPRF key. One per (device, epoch).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OprfKey(Scalar);

impl OprfKey {
    pub fn generate() -> Self {
        loop {
            let s = Scalar::random(&mut OsRng);
            if s != Scalar::ZERO {
                return OprfKey(s);
            }
        }
    }

    pub fn to_bytes(&self) -> [u8; SCALAR_LEN] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; SCALAR_LEN]) -> Result<Self> {
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
            .ok_or(Error::InvalidScalar)?;
        if s == Scalar::ZERO {
            return Err(Error::InvalidScalar);
        }
        Ok(OprfKey(s))
    }

    /// `Y = k * G`, pinned by the client at enrolment / rotation.
    pub fn public(&self) -> [u8; ELEMENT_LEN] {
        (self.0 * G).compress().to_bytes()
    }

    /// Evaluate a blinded element and prove the evaluation used this key.
    pub fn evaluate(&self, blinded: &[u8; ELEMENT_LEN]) -> Result<Evaluation> {
        let b = decode_element(blinded)?;
        let z = self.0 * b;
        let y = self.0 * G;

        let mut t = Scalar::random(&mut OsRng);
        let a1 = t * G;
        let a2 = t * b;
        let c = dleq_challenge(&y, &b, &z, &a1, &a2);
        let s = t - c * self.0;
        t.zeroize();

        Ok(Evaluation {
            evaluated: z.compress().to_bytes(),
            proof_c: c.to_bytes(),
            proof_s: s.to_bytes(),
        })
    }
}

/// What the server sends back: `Z` and the DLEQ proof `(c, s)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub evaluated: [u8; ELEMENT_LEN],
    pub proof_c: [u8; SCALAR_LEN],
    pub proof_s: [u8; SCALAR_LEN],
}

/// Client-side state kept between `blind` and `finalize`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Blinding {
    r: Scalar,
    input: Vec<u8>,
    #[zeroize(skip)]
    blinded: RistrettoPoint,
}

impl Blinding {
    pub fn new(input: &[u8]) -> Self {
        let p = hash_to_group(input);
        let r = loop {
            let r = Scalar::random(&mut OsRng);
            if r != Scalar::ZERO {
                break r;
            }
        };
        Blinding {
            r,
            input: input.to_vec(),
            blinded: r * p,
        }
    }

    pub fn blinded(&self) -> [u8; ELEMENT_LEN] {
        self.blinded.compress().to_bytes()
    }

    /// Verify the server's proof against the pinned public key, unblind, and derive the output.
    pub fn finalize(
        &self,
        eval: &Evaluation,
        server_public: &[u8; ELEMENT_LEN],
    ) -> Result<[u8; OUTPUT_LEN]> {
        let y = decode_element(server_public)?;
        let z = decode_element(&eval.evaluated)?;
        let c = decode_scalar(&eval.proof_c)?;
        let s = decode_scalar(&eval.proof_s)?;

        // Chaum-Pedersen verification: recompute the commitments and the challenge.
        let a1 = s * G + c * y;
        let a2 = s * self.blinded + c * z;
        let expect = dleq_challenge(&y, &self.blinded, &z, &a1, &a2);
        if expect != c {
            return Err(Error::BadProof);
        }

        let n = (self.r.invert() * z).compress();
        let mut h = Sha512::new();
        h.update((DST_H2.len() as u32).to_be_bytes());
        h.update(DST_H2);
        h.update((self.input.len() as u32).to_be_bytes());
        h.update(&self.input);
        h.update(n.as_bytes());
        let mut out = [0u8; OUTPUT_LEN];
        out.copy_from_slice(&h.finalize());
        Ok(out)
    }
}

fn hash_to_group(input: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update((DST_H1.len() as u32).to_be_bytes());
    h.update(DST_H1);
    h.update(input);
    RistrettoPoint::from_hash(h)
}

fn decode_element(bytes: &[u8; ELEMENT_LEN]) -> Result<RistrettoPoint> {
    let p = CompressedRistretto(*bytes)
        .decompress()
        .ok_or(Error::InvalidElement)?;
    // The identity would make Z independent of k (and leak nothing useful) – always reject.
    if p.is_identity() {
        return Err(Error::InvalidElement);
    }
    Ok(p)
}

fn decode_scalar(bytes: &[u8; SCALAR_LEN]) -> Result<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).ok_or(Error::InvalidScalar)
}

fn dleq_challenge(
    y: &RistrettoPoint,
    b: &RistrettoPoint,
    z: &RistrettoPoint,
    a1: &RistrettoPoint,
    a2: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update((DST_DLEQ.len() as u32).to_be_bytes());
    h.update(DST_DLEQ);
    for p in [&G, y, b, z, a1, a2] {
        h.update(p.compress().as_bytes());
    }
    Scalar::from_hash(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_per_key_and_input() {
        let k = OprfKey::generate();
        let run = |input: &[u8]| {
            let b = Blinding::new(input);
            let e = k.evaluate(&b.blinded()).unwrap();
            b.finalize(&e, &k.public()).unwrap()
        };
        assert_eq!(run(b"alpha"), run(b"alpha"));
        assert_ne!(run(b"alpha"), run(b"beta"));

        let k2 = OprfKey::generate();
        let b = Blinding::new(b"alpha");
        let e = k2.evaluate(&b.blinded()).unwrap();
        assert_ne!(b.finalize(&e, &k2.public()).unwrap(), run(b"alpha"));
    }

    #[test]
    fn blinded_elements_are_unlinkable() {
        // Two blindings of the same input must differ (fresh r each time).
        assert_ne!(Blinding::new(b"x").blinded(), Blinding::new(b"x").blinded());
    }

    #[test]
    fn rejects_evaluation_under_wrong_key() {
        let k = OprfKey::generate();
        let rogue = OprfKey::generate();
        let b = Blinding::new(b"input");
        let e = rogue.evaluate(&b.blinded()).unwrap();
        assert_eq!(b.finalize(&e, &k.public()), Err(Error::BadProof));
    }

    #[test]
    fn rejects_tampered_evaluation_and_proof() {
        let k = OprfKey::generate();
        let b = Blinding::new(b"input");
        let good = k.evaluate(&b.blinded()).unwrap();

        let mut bad = good.clone();
        bad.evaluated = (Scalar::from(2u8) * decode_element(&good.evaluated).unwrap())
            .compress()
            .to_bytes();
        assert_eq!(b.finalize(&bad, &k.public()), Err(Error::BadProof));

        let mut bad = good.clone();
        bad.proof_s = (decode_scalar(&good.proof_s).unwrap() + Scalar::ONE).to_bytes();
        assert_eq!(b.finalize(&bad, &k.public()), Err(Error::BadProof));
    }

    #[test]
    fn rejects_identity_and_garbage_elements() {
        let k = OprfKey::generate();
        assert_eq!(k.evaluate(&[0u8; 32]).unwrap_err(), Error::InvalidElement);
        assert_eq!(k.evaluate(&[0xff; 32]).unwrap_err(), Error::InvalidElement);
    }

    #[test]
    fn key_serialisation_roundtrip() {
        let k = OprfKey::generate();
        let k2 = OprfKey::from_bytes(&k.to_bytes()).unwrap();
        assert_eq!(k.public(), k2.public());
        assert!(OprfKey::from_bytes(&[0u8; 32]).is_err());
        assert!(OprfKey::from_bytes(&[0xff; 32]).is_err());
    }
}
