//! Shared v2 passphrase policy (CRYPTO-V2 §11 / §24).
//!
//! Operates on the exact UTF-8 input. The string passed to Argon2 is never
//! trimmed, case-folded, or Unicode-normalized. Weakness detection may inspect
//! an ASCII-lowercased *copy* of the input.

use super::v1::CryptoError;

/// Frozen floor: Unicode scalar values, not bytes.
pub const V2_PASSPHRASE_MIN_CHARS: usize = 12;

/// Common / leaked passwords. Compared case-insensitively for ASCII letters.
const COMMON: &[&str] = &[
    "password",
    "password1",
    "password12",
    "password123",
    "password1234",
    "passw0rd",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "12345678901",
    "123456789012",
    "111111",
    "111111111111",
    "000000",
    "123123",
    "654321",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "abc123",
    "abcdef",
    "abcdefghijkl",
    "letmein",
    "welcome",
    "admin",
    "login",
    "master",
    "dragon",
    "monkey",
    "football",
    "baseball",
    "iloveyou",
    "princess",
    "sunshine",
    "shadow",
    "trustno1",
    "qwertyuiopas",
];

const KEYBOARD_ROWS: &[&str] = &[
    "0123456789",
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "abcdefghijklmnopqrstuvwxyz",
];

/// Validate a passphrase that will wrap v2 secrets (vault, backup, restore).
pub fn validate_v2_passphrase(passphrase: &str) -> Result<(), CryptoError> {
    let chars: Vec<char> = passphrase.chars().collect();
    if chars.len() < V2_PASSPHRASE_MIN_CHARS {
        return Err(CryptoError::WeakPassphrase);
    }
    if is_repeated_char(&chars) {
        return Err(CryptoError::WeakPassphrase);
    }
    if is_common(passphrase) {
        return Err(CryptoError::WeakPassphrase);
    }
    if is_simple_numeric_sequence(&chars) {
        return Err(CryptoError::WeakPassphrase);
    }
    if is_keyboard_or_alpha_run(passphrase) {
        return Err(CryptoError::WeakPassphrase);
    }
    Ok(())
}

fn is_repeated_char(chars: &[char]) -> bool {
    let Some(first) = chars.first() else {
        return true;
    };
    chars.iter().all(|c| c == first)
}

fn is_common(passphrase: &str) -> bool {
    let lower = ascii_lower(passphrase);
    COMMON.iter().any(|w| *w == lower.as_str() || *w == passphrase)
}

fn ascii_lower(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

fn is_simple_numeric_sequence(chars: &[char]) -> bool {
    if chars.len() < 8 || !chars.iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let digits: Vec<i16> = chars.iter().map(|c| (*c as u8 - b'0') as i16).collect();
    let delta = digits[1] - digits[0];
    if delta.abs() != 1 {
        let wrap = (digits[1] - digits[0] + 10) % 10;
        if wrap != 1 && wrap != 9 {
            return false;
        }
        return digits
            .windows(2)
            .all(|w| (w[1] - w[0] + 10) % 10 == wrap);
    }
    digits.windows(2).all(|w| w[1] - w[0] == delta)
}

fn is_keyboard_or_alpha_run(passphrase: &str) -> bool {
    let lower = ascii_lower(passphrase);
    if lower.chars().count() < 8 {
        return false;
    }
    if !lower
        .chars()
        .all(|c| c.is_ascii_alphanumeric())
    {
        return false;
    }
    for row in KEYBOARD_ROWS {
        let rev: String = row.chars().rev().collect();
        if row.contains(&lower) || rev.contains(&lower) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::backup::create_backup;
    use crate::crypto::envelope_v2::{unwrap_root_v2, wrap_root_v2};
    use crate::session_v2::VaultSessionV2;
    use crate::types::{unix_now, VaultDocument, VaultMeta};
    use crate::vault::MemoryStore;

    fn reject(s: &str) {
        assert_eq!(
            validate_v2_passphrase(s),
            Err(CryptoError::WeakPassphrase),
            "expected reject: {s:?}"
        );
    }

    fn accept(s: &str) {
        assert_eq!(validate_v2_passphrase(s), Ok(()), "expected accept: {s:?}");
    }

    #[test]
    fn rejects_obviously_inadequate() {
        reject("");
        reject("short");
        reject("12345678");
        reject("password");
        reject("aaaaaaaaaaaa");
        reject("ABCDEFGHIJKL");
        reject("abcdefghijkl");
        reject("123456789012");
        reject("qwertyuiopas");
    }

    #[test]
    fn accepts_strong_and_preserves_exact_utf8() {
        accept("correct horse battery staple");
        accept("correct horse battery staple extra word");
        accept("xK7mQ9pL2vN8rT4wY1zB");
        accept("パスワードが十分に長いです");
        accept("  correct horse battery staple");
        accept("correct horse battery staple  ");
        let spaced = "  correct horse battery staple  ";
        accept(spaced);
        assert_ne!(spaced, spaced.trim());
        assert_eq!(spaced.len(), 32);
    }

    #[test]
    fn same_policy_on_vault_create_and_backup() {
        let rejects = ["", "short", "12345678", "password", "aaaaaaaaaaaa"];
        let doc = VaultDocument {
            meta: VaultMeta {
                vault_id: "ab".into(),
                format_version: 2,
                created_at: unix_now(),
                updated_at: unix_now(),
                device_id: "d".into(),
            },
            ..Default::default()
        };
        for s in rejects {
            reject(s);
            let mut store = MemoryStore::default();
            assert!(
                VaultSessionV2::create(&mut store, s).is_err(),
                "vault create accepted {s:?}"
            );
            assert!(
                create_backup(s, [1u8; 16], &doc, &[]).is_err(),
                "backup accepted {s:?}"
            );
        }
    }

    #[test]
    fn spaces_and_unicode_are_not_normalized_for_kdf() {
        let vid = [0x44u8; 16];
        let spaced = "  correct horse battery staple  ";
        let (env, root) = wrap_root_v2(spaced, vid).unwrap();
        let opened = unwrap_root_v2(spaced, &env).unwrap();
        assert_eq!(opened.as_bytes(), root.as_bytes());
        assert!(unwrap_root_v2(spaced.trim(), &env).is_err());

        let uni = "パスワードが十分に長いです";
        let (env, root) = wrap_root_v2(uni, vid).unwrap();
        assert_eq!(
            unwrap_root_v2(uni, &env).unwrap().as_bytes(),
            root.as_bytes()
        );
        assert!(unwrap_root_v2("パスワードが十分に長いです ", &env).is_err());
    }
}
