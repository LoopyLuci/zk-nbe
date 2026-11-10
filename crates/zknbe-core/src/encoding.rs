//! Base64url helpers and the length-prefixed transcript used for every signature and MAC.

use crate::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| Error::Encoding("not valid base64url"))
}

pub fn unb64_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    let v = unb64(s)?;
    v.try_into()
        .map_err(|_| Error::Encoding("unexpected length"))
}

/// Parse `90`, `90s`, `15m`, `4h` or `7d` into seconds.
pub fn parse_duration(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    let (digits, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .ok_or_else(|| format!("invalid duration '{s}' (expected e.g. 90s, 15m, 4h, 7d)"))
}

/// An unambiguous byte string built from typed, length-prefixed fields.
///
/// Every signed or MACed message in the protocol is a transcript that starts with a
/// domain-separation label, so a signature made for one purpose can never be replayed
/// for another.
pub struct Transcript(Vec<u8>);

impl Transcript {
    pub fn new(label: &str) -> Self {
        Transcript(Vec::with_capacity(256))
            .bytes(b"zknbe/v1")
            .str(label)
    }

    pub fn bytes(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(&(b.len() as u32).to_be_bytes());
        self.0.extend_from_slice(b);
        self
    }

    pub fn str(self, s: &str) -> Self {
        self.bytes(s.as_bytes())
    }

    pub fn u64(self, v: u64) -> Self {
        self.bytes(&v.to_be_bytes())
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_injective_across_field_boundaries() {
        let a = Transcript::new("x").str("ab").str("c").finish();
        let b = Transcript::new("x").str("a").str("bc").finish();
        assert_ne!(a, b);
    }

    #[test]
    fn b64_roundtrip() {
        let v = [0u8, 255, 3, 250, 9];
        assert_eq!(unb64(&b64(&v)).unwrap(), v);
        assert!(unb64("!!").is_err());
        assert!(unb64_array::<4>(&b64(&v)).is_err());
    }
}
