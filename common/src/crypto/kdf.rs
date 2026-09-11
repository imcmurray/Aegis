//! v2 Argon2id parameters: serialized on the wire, validated before allocate (D8 / D12).

use super::secret::{BackupWrapKek, WrapKek};
use super::CryptoError;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

/// Aegis v2 wire ID: `0x02` = Argon2id. Not an `argon2` crate discriminant.
pub const ARGON2_ALG_ARGON2ID: u8 = 0x02;
/// Argon2 spec version 19 (0x13). Aegis-owned wire constant.
pub const ARGON2_VERSION_19: u8 = 19;
pub const SALT_LEN: usize = 16;
pub const OUTPUT_LEN: u32 = 32;

pub const MAX_ARGON2_MEMORY_KIB: u32 = 262_144; // 256 MiB
pub const MAX_ARGON2_ITERATIONS: u32 = 8;
pub const MAX_ARGON2_PARALLELISM: u32 = 4;
pub const MAX_ARGON2_WORK: u64 = 786_432; // 256 MiB × t=3
pub const V2_MIN_MEMORY_KIB: u32 = 64 * 1024;
pub const V2_DEFAULT_ITERATIONS: u32 = 3;
pub const V2_DEFAULT_PARALLELISM: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfContext {
    /// New v2 envelopes. Never Test, never below 64 MiB.
    V2Generate,
    /// Imported v2 envelopes. Same floor as generate (v1 Mobile is v1-decoder only).
    V2Import,
    /// Library unit tests and native CLI `AEGIS_KDF=test`. Never a WASM generate path.
    #[cfg(any(test, feature = "insecure-kdf"))]
    V2UnitTest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Argon2ParamsV2 {
    pub algorithm: u8,
    pub version: u8,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    pub output_len: u32,
}

impl Argon2ParamsV2 {
    /// Production generate, or tiny params when `AEGIS_KDF=test` in CLI/unit tests.
    pub fn for_generate() -> Self {
        #[cfg(any(test, feature = "insecure-kdf"))]
        {
            if std::env::var("AEGIS_KDF")
                .ok()
                .map(|v| v.eq_ignore_ascii_case("test"))
                .unwrap_or(false)
            {
                return Self::insecure_for_tests();
            }
        }
        Self::generate_v2()
    }

    pub fn generate_context(&self) -> KdfContext {
        #[cfg(any(test, feature = "insecure-kdf"))]
        {
            if self.memory_kib == 8 && self.iterations == 1 && self.parallelism == 1 {
                return KdfContext::V2UnitTest;
            }
        }
        KdfContext::V2Generate
    }

    pub fn import_context(&self) -> KdfContext {
        #[cfg(any(test, feature = "insecure-kdf"))]
        {
            if self.memory_kib == 8 && self.iterations == 1 && self.parallelism == 1 {
                return KdfContext::V2UnitTest;
            }
        }
        KdfContext::V2Import
    }

    /// Production v2 generation: 64 MiB, t=3, p=1, random salt.
    pub fn generate_v2() -> Self {
        let mut salt = vec![0u8; SALT_LEN];
        crate::rng::fill_random(&mut salt);
        Self {
            algorithm: ARGON2_ALG_ARGON2ID,
            version: ARGON2_VERSION_19,
            memory_kib: V2_MIN_MEMORY_KIB,
            iterations: V2_DEFAULT_ITERATIONS,
            parallelism: V2_DEFAULT_PARALLELISM,
            salt,
            output_len: OUTPUT_LEN,
        }
    }

    /// Tiny params for unit tests of the v2 *format*. Not a production constructor.
    #[cfg(any(test, feature = "insecure-kdf"))]
    pub fn insecure_for_tests() -> Self {
        let mut salt = vec![0u8; SALT_LEN];
        crate::rng::fill_random(&mut salt);
        Self {
            algorithm: ARGON2_ALG_ARGON2ID,
            version: ARGON2_VERSION_19,
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
            salt,
            output_len: OUTPUT_LEN,
        }
    }

    pub fn validate(&self, ctx: KdfContext) -> Result<(), CryptoError> {
        if wire_argon2_algorithm(self.algorithm).is_err()
            || wire_argon2_version(self.version).is_err()
        {
            return Err(CryptoError::InvalidKdfParams);
        }
        if self.salt.len() != SALT_LEN || self.output_len != OUTPUT_LEN {
            return Err(CryptoError::InvalidKdfParams);
        }
        if self.iterations == 0 || self.iterations > MAX_ARGON2_ITERATIONS {
            return Err(CryptoError::InvalidKdfParams);
        }
        if self.parallelism == 0 || self.parallelism > MAX_ARGON2_PARALLELISM {
            return Err(CryptoError::InvalidKdfParams);
        }
        if self.memory_kib == 0 || self.memory_kib > MAX_ARGON2_MEMORY_KIB {
            return Err(CryptoError::InvalidKdfParams);
        }
        let work = argon2_work_factor(self.memory_kib, self.iterations)?;
        if work > MAX_ARGON2_WORK {
            return Err(CryptoError::InvalidKdfParams);
        }
        match ctx {
            KdfContext::V2Generate | KdfContext::V2Import => {
                if self.memory_kib < V2_MIN_MEMORY_KIB {
                    return Err(CryptoError::InvalidKdfParams);
                }
            }
            #[cfg(any(test, feature = "insecure-kdf"))]
            KdfContext::V2UnitTest => {}
        }
        Ok(())
    }

    /// Canonical bytes for backup AAD. Not CBOR map order.
    pub fn aad_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + 4 * 4 + 4 + self.salt.len());
        out.push(self.algorithm);
        out.push(self.version);
        out.extend_from_slice(&self.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.iterations.to_le_bytes());
        out.extend_from_slice(&self.parallelism.to_le_bytes());
        out.extend_from_slice(&self.output_len.to_le_bytes());
        out.extend_from_slice(&(self.salt.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.salt);
        out
    }

    /// Validate then build argon2::Params. Never allocates the hasher memory itself.
    pub fn to_argon2_params(&self, ctx: KdfContext) -> Result<Params, CryptoError> {
        self.validate(ctx)?;
        Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(OUTPUT_LEN as usize),
        )
        .map_err(|e| CryptoError::Kdf(e.to_string()))
    }
}

fn wire_argon2_algorithm(id: u8) -> Result<Algorithm, CryptoError> {
    match id {
        ARGON2_ALG_ARGON2ID => Ok(Algorithm::Argon2id),
        _ => Err(CryptoError::InvalidKdfParams),
    }
}

fn wire_argon2_version(v: u8) -> Result<Version, CryptoError> {
    match v {
        ARGON2_VERSION_19 => Ok(Version::V0x13),
        _ => Err(CryptoError::InvalidKdfParams),
    }
}

/// `memory_kib * iterations` as u64. Checked so a future type change cannot wrap under the cap.
pub fn argon2_work_factor(memory_kib: u32, iterations: u32) -> Result<u64, CryptoError> {
    u64::from(memory_kib)
        .checked_mul(u64::from(iterations))
        .ok_or(CryptoError::InvalidKdfParams)
}

pub fn derive_kek(
    passphrase: &str,
    params: &Argon2ParamsV2,
    ctx: KdfContext,
) -> Result<WrapKek, CryptoError> {
    let p = params.to_argon2_params(ctx)?;
    let argon2 = Argon2::new(
        wire_argon2_algorithm(params.algorithm)?,
        wire_argon2_version(params.version)?,
        p,
    );
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &params.salt, &mut out)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(WrapKek::from_bytes(out))
}

pub fn derive_backup_wrap_kek(
    passphrase: &str,
    params: &Argon2ParamsV2,
    ctx: KdfContext,
) -> Result<BackupWrapKek, CryptoError> {
    let kek = derive_kek(passphrase, params, ctx)?;
    Ok(BackupWrapKek::from_bytes(*kek.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d12_rejects_work_overflow_combination() {
        let mut p = Argon2ParamsV2::insecure_for_tests();
        p.memory_kib = 256 * 1024;
        p.iterations = 8;
        assert!(p.validate(KdfContext::V2Import).is_err());
    }

    #[test]
    fn d12_work_factor_is_checked_u64_and_does_not_wrap() {
        // Two u32s cannot overflow u64; the helper must still use checked_mul and
        // must not wrap to a value under MAX_ARGON2_WORK.
        let work = argon2_work_factor(u32::MAX, u32::MAX).expect("u32*u32 fits in u64");
        assert_eq!(work, u64::from(u32::MAX) * u64::from(u32::MAX));
        assert!(work > MAX_ARGON2_WORK);
        let mut p = Argon2ParamsV2::insecure_for_tests();
        p.memory_kib = u32::MAX;
        p.iterations = u32::MAX;
        assert_eq!(
            p.validate(KdfContext::V2Import),
            Err(CryptoError::InvalidKdfParams)
        );
    }

    #[test]
    fn d12_rejects_v1_mobile_on_v2_import() {
        let mut p = Argon2ParamsV2::generate_v2();
        p.memory_kib = 32 * 1024;
        p.iterations = 2;
        assert!(p.validate(KdfContext::V2Import).is_err());
        assert!(p.validate(KdfContext::V2Generate).is_err());
        assert!(p.to_argon2_params(KdfContext::V2Import).is_err());
    }

    #[test]
    fn d12_to_argon2_params_rejects_before_hasher() {
        let mut p = Argon2ParamsV2::generate_v2();
        p.memory_kib = 256 * 1024;
        p.iterations = 8;
        assert!(p.to_argon2_params(KdfContext::V2Import).is_err());
        assert!(derive_kek("pw", &p, KdfContext::V2Import).is_err());
    }

    #[test]
    fn d12_allows_measured_cap() {
        let mut p = Argon2ParamsV2::generate_v2();
        p.memory_kib = 256 * 1024;
        p.iterations = 3;
        assert!(p.validate(KdfContext::V2Import).is_ok());
    }

    #[test]
    fn v2_generate_rejects_below_64_mib() {
        let p = Argon2ParamsV2::insecure_for_tests();
        assert!(p.validate(KdfContext::V2Generate).is_err());
        assert!(p.validate(KdfContext::V2Import).is_err());
    }

    #[test]
    fn production_generate_meets_floor() {
        let p = Argon2ParamsV2::generate_v2();
        assert!(p.validate(KdfContext::V2Generate).is_ok());
        assert_eq!(p.memory_kib, 64 * 1024);
        assert_eq!(p.algorithm, ARGON2_ALG_ARGON2ID);
        assert_eq!(p.algorithm, 0x02);
        assert_eq!(p.version, ARGON2_VERSION_19);
        assert_eq!(p.salt.len(), 16);
    }

    #[test]
    fn argon2_algorithm_id_is_aegis_owned_and_fail_closed() {
        assert_eq!(ARGON2_ALG_ARGON2ID, 0x02);
        assert_eq!(
            wire_argon2_algorithm(ARGON2_ALG_ARGON2ID).unwrap(),
            Algorithm::Argon2id
        );
        // RFC 9106 uses 0/1/2 for d/i/id; Aegis v2 only allows 0x02.
        assert!(wire_argon2_algorithm(0).is_err());
        assert!(wire_argon2_algorithm(1).is_err());
        assert!(wire_argon2_algorithm(3).is_err());
        let mut p = Argon2ParamsV2::generate_v2();
        p.algorithm = 0;
        assert_eq!(p.validate(KdfContext::V2Import), Err(CryptoError::InvalidKdfParams));
        p.algorithm = ARGON2_ALG_ARGON2ID;
        p.version = 0x10;
        assert_eq!(p.validate(KdfContext::V2Import), Err(CryptoError::InvalidKdfParams));
    }
}
