//! ZK-NBE cryptographic core.
//!
//! * [`oprf`]   – verifiable oblivious PRF over ristretto255 (2HashDH + DLEQ proof)
//! * [`shamir`] – t-of-n secret sharing over GF(2^8)
//! * [`keys`]   – key hierarchy: everything derived from the device secret and the volume master key
//! * [`wrap`]   – authenticated encryption of small secrets
//! * [`proto`]  – wire messages and the signed transcripts that bind them
//!
//! Nothing in this crate performs I/O.

pub mod encoding;
pub mod keys;
pub mod oprf;
pub mod proto;
pub mod shamir;
pub mod wrap;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid encoding: {0}")]
    Encoding(&'static str),
    #[error("invalid group element")]
    InvalidElement,
    #[error("invalid scalar")]
    InvalidScalar,
    #[error("server evaluation proof did not verify")]
    BadProof,
    #[error("signature or MAC did not verify")]
    BadSignature,
    #[error("authenticated decryption failed")]
    Decrypt,
    #[error("secret sharing: {0}")]
    Shamir(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
