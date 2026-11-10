//! Shamir secret sharing over GF(2^8), applied byte-wise.
//!
//! Any `threshold` shares reconstruct the secret; fewer reveal nothing (information
//! theoretically). Share indices are the x-coordinates 1..=n. Field arithmetic is branch-free.

use crate::{Error, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & 0u8.wrapping_sub(b & 1);
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & carry);
        b >>= 1;
    }
    p
}

fn gf_inv(a: u8) -> u8 {
    // a^254 by square-and-multiply; maps 0 -> 0, which callers exclude.
    let mut result = 1u8;
    let mut base = a;
    let mut e = 254u8;
    while e > 0 {
        if e & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    result
}

pub fn split(secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<Share>> {
    if threshold == 0 || shares == 0 || threshold > shares {
        return Err(Error::Shamir("need 1 <= threshold <= shares <= 255"));
    }
    if secret.is_empty() {
        return Err(Error::Shamir("empty secret"));
    }
    let mut out: Vec<Share> = (1..=shares)
        .map(|index| Share {
            index,
            data: Vec::with_capacity(secret.len()),
        })
        .collect();
    let mut coeffs = vec![0u8; threshold as usize];
    for &byte in secret {
        coeffs[0] = byte;
        OsRng.fill_bytes(&mut coeffs[1..]);
        for share in out.iter_mut() {
            // Horner evaluation at x = index.
            let y = coeffs
                .iter()
                .rev()
                .fold(0u8, |acc, &c| gf_mul(acc, share.index) ^ c);
            share.data.push(y);
        }
    }
    coeffs.zeroize();
    Ok(out)
}

/// Reconstruct from exactly the shares given (the caller picks `threshold` of them).
/// Supplying fewer than the threshold yields garbage, not an error – callers must verify the
/// result against a key-check value.
pub fn combine(shares: &[Share]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(Error::Shamir("no shares"));
    }
    let len = shares[0].data.len();
    for (i, s) in shares.iter().enumerate() {
        if s.index == 0 || s.data.len() != len {
            return Err(Error::Shamir("malformed share"));
        }
        if shares[..i].iter().any(|o| o.index == s.index) {
            return Err(Error::Shamir("duplicate share index"));
        }
    }
    // Lagrange basis at x = 0: l_i = prod_{j != i} x_j / (x_j - x_i); subtraction is XOR.
    let basis: Vec<u8> = shares
        .iter()
        .map(|si| {
            shares
                .iter()
                .filter(|sj| sj.index != si.index)
                .fold(1u8, |acc, sj| {
                    gf_mul(acc, gf_mul(sj.index, gf_inv(sj.index ^ si.index)))
                })
        })
        .collect();
    Ok((0..len)
        .map(|pos| {
            shares
                .iter()
                .zip(&basis)
                .fold(0u8, |acc, (s, &l)| acc ^ gf_mul(s.data[pos], l))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_axioms() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a}");
            assert_eq!(gf_mul(a, 1), a);
        }
        assert_eq!(gf_mul(0x57, 0x83), 0xc1); // FIPS-197 worked example
    }

    #[test]
    fn every_threshold_subset_reconstructs() {
        let secret: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(37) ^ 0xa5).collect();
        let shares = split(&secret, 3, 5).unwrap();
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let subset = [shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(combine(&subset).unwrap(), secret);
                }
            }
        }
        assert_eq!(combine(&shares).unwrap(), secret);
    }

    #[test]
    fn below_threshold_does_not_reconstruct() {
        let secret = [7u8; 32];
        let shares = split(&secret, 3, 5).unwrap();
        assert_ne!(combine(&shares[..2]).unwrap(), secret);
    }

    #[test]
    fn degenerate_parameters() {
        assert_eq!(combine(&split(b"k", 1, 1).unwrap()).unwrap(), b"k");
        assert!(split(b"k", 0, 3).is_err());
        assert!(split(b"k", 4, 3).is_err());
        assert!(split(b"", 1, 1).is_err());
        let s = split(b"abcd", 2, 2).unwrap();
        assert!(combine(&[s[0].clone(), s[0].clone()]).is_err());
    }
}
