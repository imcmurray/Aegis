//! Hybrid key establishment: X25519 AND ML-KEM-768 with the D5 combiner.
//!
//! `ikm = mlkem_ss || x25519_ss`. All-zero X25519 shared secret is rejected
//! before HKDF. Combiner info is exactly `aegis/v2/share/hybrid-kek`.

use super::hkdf_v2::LABEL_SHARE_HYBRID_KEK;
use super::secret::{HybridShareSecret, ShareMlkemSeed, ShareX25519Seed};
use super::v1::CryptoError;
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, KeyExport, TryKeyInit};
use ml_kem::{
    B32, Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768, Seed as MlKemSeed,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

pub const X25519_PK_LEN: usize = 32;
pub const MLKEM_768_EK_LEN: usize = 1184;
pub const MLKEM_768_CT_LEN: usize = 1088;

pub struct ShareKemRecipient {
    pub x25519_pk: [u8; 32],
    pub mlkem_ek: Vec<u8>,
}

pub struct HybridEncap {
    pub ephemeral_x25519_pk: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
    pub secret: HybridShareSecret,
}

pub fn x25519_public_from_seed(seed: &ShareX25519Seed) -> [u8; 32] {
    let sk = StaticSecret::from(*seed.as_bytes());
    *X25519Public::from(&sk).as_bytes()
}

pub fn mlkem_ek_from_seed(seed: &ShareMlkemSeed) -> Result<Vec<u8>, CryptoError> {
    let dk = mlkem_dk(seed)?;
    Ok(dk.encapsulation_key().to_bytes().to_vec())
}

fn mlkem_dk(seed: &ShareMlkemSeed) -> Result<DecapsulationKey<MlKem768>, CryptoError> {
    let seed = MlKemSeed::try_from(seed.as_bytes().as_slice())
        .map_err(|_| CryptoError::KeyLength)?;
    Ok(DecapsulationKey::<MlKem768>::from_seed(seed))
}

fn mlkem_ek_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey<MlKem768>, CryptoError> {
    if bytes.len() != MLKEM_768_EK_LEN {
        return Err(CryptoError::InvalidEnvelope);
    }
    EncapsulationKey::<MlKem768>::new_from_slice(bytes)
        .map_err(|_| CryptoError::InvalidEnvelope)
}

fn is_all_zero(ss: &[u8; 32]) -> bool {
    ss.ct_eq(&[0u8; 32]).into()
}

/// D5 combiner. `transcript` is the D1 share transcript; salt is SHA-256(transcript).
pub fn combine_hybrid_secret(
    mlkem_ss: &[u8; 32],
    x25519_ss: &[u8; 32],
    transcript: &[u8],
) -> Result<HybridShareSecret, CryptoError> {
    if is_all_zero(x25519_ss) {
        return Err(CryptoError::ZeroSharedSecret);
    }
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(mlkem_ss);
    ikm[32..].copy_from_slice(x25519_ss);
    let transcript_hash = Sha256::digest(transcript);
    let hk = Hkdf::<Sha256>::new(Some(transcript_hash.as_slice()), &ikm);
    let mut out = [0u8; 32];
    hk.expand(LABEL_SHARE_HYBRID_KEK, &mut out)
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(HybridShareSecret::from_bytes(out))
}

pub fn encapsulate_hybrid(
    sender_eph_sk: &StaticSecret,
    recipient: &ShareKemRecipient,
    transcript_without_eph_and_ct: impl Fn(&[u8], &[u8]) -> Vec<u8>,
) -> Result<HybridEncap, CryptoError> {
    if recipient.x25519_pk.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidEnvelope);
    }
    let eph_pk = *X25519Public::from(sender_eph_sk).as_bytes();
    let their_x = X25519Public::from(recipient.x25519_pk);
    let x_ss = *sender_eph_sk.diffie_hellman(&their_x).as_bytes();
    if is_all_zero(&x_ss) {
        return Err(CryptoError::ZeroSharedSecret);
    }

    let ek = mlkem_ek_from_bytes(&recipient.mlkem_ek)?;
    let mut m = [0u8; 32];
    crate::rng::fill_random(&mut m);
    let m = B32::from(m);
    let (ct, mlkem_ss) = ek.encapsulate_deterministic(&m);
    let ct_bytes = ct.to_vec();
    if ct_bytes.len() != MLKEM_768_CT_LEN {
        return Err(CryptoError::InvalidEnvelope);
    }

    let transcript = transcript_without_eph_and_ct(&eph_pk, &ct_bytes);
    let mut mlkem_ss_arr = [0u8; 32];
    mlkem_ss_arr.copy_from_slice(mlkem_ss.as_slice());
    let secret = combine_hybrid_secret(&mlkem_ss_arr, &x_ss, &transcript)?;
    Ok(HybridEncap {
        ephemeral_x25519_pk: eph_pk,
        mlkem_ciphertext: ct_bytes,
        secret,
    })
}

pub fn decapsulate_hybrid(
    recipient_x25519_seed: &ShareX25519Seed,
    recipient_mlkem_seed: &ShareMlkemSeed,
    ephemeral_x25519: &[u8; 32],
    mlkem_ciphertext: &[u8],
    transcript: &[u8],
) -> Result<HybridShareSecret, CryptoError> {
    if mlkem_ciphertext.len() != MLKEM_768_CT_LEN {
        return Err(CryptoError::InvalidEnvelope);
    }
    let eph = X25519Public::from(*ephemeral_x25519);
    let sk = StaticSecret::from(*recipient_x25519_seed.as_bytes());
    let x_ss = *sk.diffie_hellman(&eph).as_bytes();
    if is_all_zero(&x_ss) {
        return Err(CryptoError::ZeroSharedSecret);
    }
    let dk = mlkem_dk(recipient_mlkem_seed)?;
    let ct = Ciphertext::<MlKem768>::try_from(mlkem_ciphertext)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let mlkem_ss = dk.decapsulate(&ct);
    let mut mlkem_ss_arr = [0u8; 32];
    mlkem_ss_arr.copy_from_slice(mlkem_ss.as_slice());
    combine_hybrid_secret(&mlkem_ss_arr, &x_ss, transcript)
}

pub fn random_ephemeral_x25519() -> StaticSecret {
    let mut seed = [0u8; 32];
    crate::rng::fill_random(&mut seed);
    StaticSecret::from(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hkdf_v2::derive_operational_keys;
    use crate::crypto::secret::RootSecret;

    #[test]
    fn fips_sizes() {
        let keys = derive_operational_keys(&RootSecret::from_bytes([3; 32]), &[1u8; 16]).unwrap();
        assert_eq!(x25519_public_from_seed(&keys.share_x25519_seed).len(), 32);
        assert_eq!(
            mlkem_ek_from_seed(&keys.share_mlkem_seed).unwrap().len(),
            MLKEM_768_EK_LEN
        );
    }

    #[test]
    fn all_zero_x25519_is_rejected_before_combiner() {
        let mlkem = [1u8; 32];
        let zero = [0u8; 32];
        assert_eq!(
            combine_hybrid_secret(&mlkem, &zero, b"transcript").unwrap_err(),
            CryptoError::ZeroSharedSecret
        );
    }

    #[test]
    fn changing_either_component_changes_hybrid_secret() {
        let a = combine_hybrid_secret(&[1u8; 32], &[2u8; 32], b"t").unwrap();
        let b = combine_hybrid_secret(&[9u8; 32], &[2u8; 32], b"t").unwrap();
        let c = combine_hybrid_secret(&[1u8; 32], &[9u8; 32], b"t").unwrap();
        let d = combine_hybrid_secret(&[1u8; 32], &[2u8; 32], b"u").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
        assert_ne!(a.as_bytes(), d.as_bytes());
        assert_eq!(
            combine_hybrid_secret(&[1u8; 32], &[2u8; 32], b"t")
                .unwrap()
                .as_bytes(),
            a.as_bytes()
        );
    }

    #[test]
    fn ikm_is_mlkem_then_x25519() {
        // Same bytes swapped must not collide with D5 order.
        let mlkem = [0x11u8; 32];
        let x = [0x22u8; 32];
        let forward = combine_hybrid_secret(&mlkem, &x, b"t").unwrap();
        let swapped = combine_hybrid_secret(&x, &mlkem, b"t").unwrap();
        assert_ne!(forward.as_bytes(), swapped.as_bytes());
    }
}
