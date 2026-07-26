//! RFC 6238 TOTP (HMAC-SHA1, 30s, 6 digits by default).
//!
//! Secrets are accepted as standard Base32 (as exported by Google Authenticator, etc.).

use hmac::{Hmac, Mac};
use sha1::Sha1;
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("empty secret")]
    EmptySecret,
    #[error("invalid base32 secret")]
    InvalidBase32,
    #[error("hmac error")]
    Hmac,
}

/// Generate a TOTP code for `secret_base32` at `time_secs` (unix).
pub fn generate_totp(
    secret_base32: &str,
    time_secs: u64,
    period: u64,
    digits: u32,
) -> Result<String, TotpError> {
    let period = period.max(1);
    let digits = digits.clamp(6, 8);
    let key = decode_base32(secret_base32)?;
    if key.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    let counter = time_secs / period;
    let mut msg = [0u8; 8];
    msg.copy_from_slice(&counter.to_be_bytes());

    let mut mac = HmacSha1::new_from_slice(&key).map_err(|_| TotpError::Hmac)?;
    mac.update(&msg);
    let hash = mac.finalize().into_bytes();

    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    let modulo = 10u32.pow(digits);
    let code = bin % modulo;
    Ok(format!("{:0width$}", code, width = digits as usize))
}

/// Seconds remaining in the current TOTP window.
pub fn totp_seconds_remaining(time_secs: u64, period: u64) -> u64 {
    let period = period.max(1);
    period - (time_secs % period)
}

/// Decode Base32 (RFC 4648 alphabet, case-insensitive, ignores spaces and `=`).
fn decode_base32(input: &str) -> Result<Vec<u8>, TotpError> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(TotpError::EmptySecret);
    }

    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(cleaned.len() * 5 / 8);

    for c in cleaned.chars() {
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return Err(TotpError::InvalidBase32),
        };
        bits = (bits << 5) | val;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B test vector (secret = "12345678901234567890" as ASCII,
    /// which is Base32 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`).
    #[test]
    fn rfc6238_sha1_vectors() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        // T = 59 → 94287082 (8 digits in RFC; we use 6 by default for apps)
        let code6 = generate_totp(secret, 59, 30, 6).unwrap();
        assert_eq!(code6, "287082");
        let code8 = generate_totp(secret, 59, 30, 8).unwrap();
        assert_eq!(code8, "94287082");
    }

    #[test]
    fn remaining_seconds() {
        assert_eq!(totp_seconds_remaining(0, 30), 30);
        assert_eq!(totp_seconds_remaining(29, 30), 1);
        assert_eq!(totp_seconds_remaining(30, 30), 30);
    }
}
