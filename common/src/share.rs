//! Phase 8 hybrid sharing: authenticated X25519 + ML-KEM-768 envelopes.
//!
//! **Epoch-bound policy:** share identities live at one `key_epoch`. Full
//! RootSecret rotation mints new X25519 and ML-KEM keys; old share private
//! material is not retained. An unopened envelope addressed to epoch N is
//! not decryptable after the recipient rotates to N+1. Sender attribution
//! requires the expected sender identity snapshot (vault_id + key_epoch +
//! hybrid signing keys); an envelope signed at an old sender epoch is not
//! accepted as the sender's current identity. Previously imported plaintext
//! is unaffected.

use crate::crypto::aead;
use crate::crypto::hybrid_kem::{
    decapsulate_hybrid, encapsulate_hybrid, mlkem_ek_from_seed, random_ephemeral_x25519,
    x25519_public_from_seed, ShareKemRecipient, MLKEM_768_CT_LEN, MLKEM_768_EK_LEN, X25519_PK_LEN,
};
use crate::crypto::hybrid_sign::{
    verify_hybrid, HybridSignatureV2, HybridSyncIdentityV2, HybridSyncSigner, ED25519_SIG_LEN,
    ML_DSA_65_SIG_LEN,
};
use crate::crypto::secret::{OperationalKeys, ShareContentKey};
use crate::crypto::suite::{CryptoSuiteId, FORMAT_VERSION_V2};
use crate::crypto::transcript::{
    build_share_identity_transcript, build_share_payload_transcript, build_share_transcript,
};
use crate::crypto::CryptoError;
use crate::types::Entry;
use serde::{Deserialize, Serialize};

/// Share identity/envelope files are CBOR without D10 magic. Cap before parse.
pub const MAX_SHARE_FILE: usize = 1024 * 1024;

/// Recipient hybrid sharing identity. Both KEM keys are certified together
/// by the hybrid signing identity — they are not independently trusted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SharePublicIdentityV2 {
    pub format_version: u16,
    pub crypto_suite: CryptoSuiteId,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub key_epoch: u32,
    #[serde(with = "serde_bytes")]
    pub x25519_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ml_kem_768_public_key: Vec<u8>,
    pub signing_identity: HybridSyncIdentityV2,
    #[serde(with = "serde_bytes")]
    pub ed25519_signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ml_dsa_signature: Vec<u8>,
}

impl SharePublicIdentityV2 {
    pub fn validate_header(&self) -> Result<(), CryptoError> {
        if self.format_version != FORMAT_VERSION_V2 {
            return Err(CryptoError::UnsupportedVersion(self.format_version));
        }
        self.crypto_suite.require_v2_share_hybrid()?;
        if self.vault_id.len() != 16
            || self.x25519_public_key.len() != X25519_PK_LEN
            || self.ml_kem_768_public_key.len() != MLKEM_768_EK_LEN
            || self.ed25519_signature.len() != ED25519_SIG_LEN
            || self.ml_dsa_signature.len() != ML_DSA_65_SIG_LEN
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        self.signing_identity.validate()?;
        Ok(())
    }

    pub fn vault_id_bytes(&self) -> Result<[u8; 16], CryptoError> {
        self.vault_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)
    }

    pub fn kem_recipient(&self) -> Result<ShareKemRecipient, CryptoError> {
        self.validate_header()?;
        Ok(ShareKemRecipient {
            x25519_pk: self
                .x25519_public_key
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidEnvelope)?,
            mlkem_ek: self.ml_kem_768_public_key.clone(),
        })
    }

    pub fn identity_metadata(&self) -> Result<Vec<u8>, CryptoError> {
        self.validate_header()?;
        let mut out = Vec::new();
        out.extend_from_slice(&self.x25519_public_key);
        out.extend_from_slice(&self.ml_kem_768_public_key);
        out.extend_from_slice(&self.signing_identity.metadata()?);
        Ok(out)
    }

    pub fn signing_transcript(&self) -> Result<Vec<u8>, CryptoError> {
        let vault_id = self.vault_id_bytes()?;
        Ok(build_share_identity_transcript(
            &vault_id,
            self.key_epoch,
            &self.x25519_public_key,
            &self.ml_kem_768_public_key,
            &self.signing_identity.metadata()?,
        ))
    }

    pub fn hybrid_signature(&self) -> HybridSignatureV2 {
        HybridSignatureV2 {
            ed25519: self.ed25519_signature.clone(),
            ml_dsa: self.ml_dsa_signature.clone(),
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| CryptoError::Serde(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_SHARE_FILE {
            return Err(CryptoError::ResourceLimit);
        }
        let id: Self =
            ciborium::from_reader(bytes).map_err(|e| CryptoError::Serde(e.to_string()))?;
        verify_share_identity(&id)?;
        Ok(id)
    }
}

/// Verify that both KEM public keys are bound by the hybrid signing identity.
pub fn verify_share_identity(id: &SharePublicIdentityV2) -> Result<(), CryptoError> {
    id.validate_header()?;
    let transcript = id.signing_transcript()?;
    verify_hybrid(
        &id.signing_identity,
        &transcript,
        &id.hybrid_signature(),
    )
    .map_err(|_| CryptoError::UnauthorizedShareIdentity)
}

pub fn export_share_identity(
    keys: &OperationalKeys,
    vault_id: [u8; 16],
    key_epoch: u32,
) -> Result<SharePublicIdentityV2, CryptoError> {
    let signer = HybridSyncSigner::from_operational_keys(keys);
    let signing_identity = signer.identity();
    let x25519_public_key = x25519_public_from_seed(&keys.share_x25519_seed).to_vec();
    let ml_kem_768_public_key = mlkem_ek_from_seed(&keys.share_mlkem_seed)?;
    let transcript = build_share_identity_transcript(
        &vault_id,
        key_epoch,
        &x25519_public_key,
        &ml_kem_768_public_key,
        &signing_identity.metadata()?,
    );
    let sig = signer.sign(&transcript);
    let id = SharePublicIdentityV2 {
        format_version: FORMAT_VERSION_V2,
        crypto_suite: CryptoSuiteId::AegisV2ShareHybrid2026,
        vault_id: vault_id.to_vec(),
        key_epoch,
        x25519_public_key,
        ml_kem_768_public_key,
        signing_identity,
        ed25519_signature: sig.ed25519,
        ml_dsa_signature: sig.ml_dsa,
    };
    verify_share_identity(&id)?;
    Ok(id)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShareEnvelopeV2 {
    pub format_version: u16,
    pub crypto_suite: CryptoSuiteId,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub key_epoch: u32,
    #[serde(with = "serde_bytes")]
    pub share_id: Vec<u8>,
    pub sender_identity: HybridSyncIdentityV2,
    pub recipient_identity: SharePublicIdentityV2,
    #[serde(with = "serde_bytes")]
    pub ephemeral_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub mlkem_ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub wrap_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub wrapped_content_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub payload_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub payload_ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ed25519_signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ml_dsa_signature: Vec<u8>,
}

impl ShareEnvelopeV2 {
    pub fn validate_header(&self) -> Result<(), CryptoError> {
        if self.format_version != FORMAT_VERSION_V2 {
            return Err(CryptoError::UnsupportedVersion(self.format_version));
        }
        self.crypto_suite.require_v2_share_hybrid()?;
        if self.vault_id.len() != 16
            || self.share_id.len() != 16
            || self.ephemeral_x25519.len() != X25519_PK_LEN
            || self.mlkem_ciphertext.len() != MLKEM_768_CT_LEN
            || self.wrap_nonce.len() != aead::NONCE_LEN
            || self.payload_nonce.len() != aead::NONCE_LEN
            || self.ed25519_signature.len() != ED25519_SIG_LEN
            || self.ml_dsa_signature.len() != ML_DSA_65_SIG_LEN
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.crypto_suite.to_u16() == 0x0003
            || self.crypto_suite == CryptoSuiteId::AegisV2Core2026
            || self.crypto_suite == CryptoSuiteId::AegisV1Legacy
        {
            return Err(CryptoError::UnsupportedSuite(self.crypto_suite.to_u16()));
        }
        self.sender_identity.validate()?;
        Ok(())
    }

    pub fn vault_id_bytes(&self) -> Result<[u8; 16], CryptoError> {
        self.vault_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)
    }

    pub fn signing_transcript(&self) -> Result<Vec<u8>, CryptoError> {
        let vault_id = self.vault_id_bytes()?;
        Ok(build_share_transcript(
            &vault_id,
            self.key_epoch,
            &self.sender_identity.metadata()?,
            &self.recipient_identity.identity_metadata()?,
            &self.ephemeral_x25519,
            &self.recipient_identity.x25519_public_key,
            &self.recipient_identity.ml_kem_768_public_key,
            &self.mlkem_ciphertext,
            &self.share_id,
        ))
    }

    pub fn hybrid_signature(&self) -> HybridSignatureV2 {
        HybridSignatureV2 {
            ed25519: self.ed25519_signature.clone(),
            ml_dsa: self.ml_dsa_signature.clone(),
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| CryptoError::Serde(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_SHARE_FILE {
            return Err(CryptoError::ResourceLimit);
        }
        let env: Self =
            ciborium::from_reader(bytes).map_err(|e| CryptoError::Serde(e.to_string()))?;
        env.validate_header()?;
        Ok(env)
    }
}

fn verify_share_envelope_signatures(env: &ShareEnvelopeV2) -> Result<(), CryptoError> {
    env.validate_header()?;
    verify_share_identity(&env.recipient_identity)?;
    let transcript = env.signing_transcript()?;
    verify_hybrid(
        &env.sender_identity,
        &transcript,
        &env.hybrid_signature(),
    )
}

/// Wire sender keys must equal the trusted identity snapshot *before* signature
/// verification is treated as attribution. `expected` is the sender's exported
/// [`SharePublicIdentityV2`] (vault_id + key_epoch + signing keys).
pub fn authorize_share_sender(
    expected: &SharePublicIdentityV2,
    env: &ShareEnvelopeV2,
) -> Result<(), CryptoError> {
    verify_share_identity(expected)?;
    env.validate_header()?;
    if expected.signing_identity != env.sender_identity
        || expected.vault_id != env.vault_id
        || expected.key_epoch != env.key_epoch
    {
        return Err(CryptoError::UnauthorizedShareSender);
    }
    Ok(())
}

pub fn create_share_envelope(
    keys: &OperationalKeys,
    sender_vault_id: [u8; 16],
    sender_epoch: u32,
    recipient: &SharePublicIdentityV2,
    entry: &Entry,
) -> Result<ShareEnvelopeV2, CryptoError> {
    verify_share_identity(recipient)?;
    let signer = HybridSyncSigner::from_operational_keys(keys);
    let sender_identity = signer.identity();
    let kem = recipient.kem_recipient()?;

    let mut share_id = [0u8; 16];
    crate::rng::fill_random(&mut share_id);
    let eph = random_ephemeral_x25519();
    let sender_meta = sender_identity.metadata()?;
    let recipient_meta = recipient.identity_metadata()?;

    let build_t = |eph_pk: &[u8], ct: &[u8]| {
        build_share_transcript(
            &sender_vault_id,
            sender_epoch,
            &sender_meta,
            &recipient_meta,
            eph_pk,
            &recipient.x25519_public_key,
            &recipient.ml_kem_768_public_key,
            ct,
            &share_id,
        )
    };
    let encap = encapsulate_hybrid(&eph, &kem, build_t)?;
    let transcript = build_t(&encap.ephemeral_x25519_pk, &encap.mlkem_ciphertext);

    let content_key = ShareContentKey::random();
    let (wrap_nonce, wrapped_content_key) =
        aead::seal(encap.secret.as_bytes(), &transcript, content_key.as_bytes())?;

    let mut payload = Vec::new();
    ciborium::into_writer(entry, &mut payload)
        .map_err(|e| CryptoError::Serde(e.to_string()))?;
    let payload_aad =
        build_share_payload_transcript(&sender_vault_id, sender_epoch, &share_id);
    let (payload_nonce, payload_ciphertext) =
        aead::seal(content_key.as_bytes(), &payload_aad, &payload)?;

    let sig = signer.sign(&transcript);
    let env = ShareEnvelopeV2 {
        format_version: FORMAT_VERSION_V2,
        crypto_suite: CryptoSuiteId::AegisV2ShareHybrid2026,
        vault_id: sender_vault_id.to_vec(),
        key_epoch: sender_epoch,
        share_id: share_id.to_vec(),
        sender_identity,
        recipient_identity: recipient.clone(),
        ephemeral_x25519: encap.ephemeral_x25519_pk.to_vec(),
        mlkem_ciphertext: encap.mlkem_ciphertext,
        wrap_nonce: wrap_nonce.to_vec(),
        wrapped_content_key,
        payload_nonce: payload_nonce.to_vec(),
        payload_ciphertext,
        ed25519_signature: sig.ed25519,
        ml_dsa_signature: sig.ml_dsa,
    };
    verify_share_envelope_signatures(&env)?;
    Ok(env)
}

pub fn open_share_envelope(
    keys: &OperationalKeys,
    local_vault_id: [u8; 16],
    local_epoch: u32,
    env: &ShareEnvelopeV2,
    expected_sender: &SharePublicIdentityV2,
) -> Result<Entry, CryptoError> {
    authorize_share_sender(expected_sender, env)?;
    verify_share_envelope_signatures(env)?;
    let local = export_share_identity(keys, local_vault_id, local_epoch)?;
    if env.recipient_identity.x25519_public_key != local.x25519_public_key
        || env.recipient_identity.ml_kem_768_public_key != local.ml_kem_768_public_key
        || env.recipient_identity.key_epoch != local_epoch
        || env.recipient_identity.vault_id != local.vault_id
    {
        return Err(CryptoError::UnauthorizedShareIdentity);
    }
    let eph: [u8; 32] = env
        .ephemeral_x25519
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let transcript = env.signing_transcript()?;
    let hybrid = decapsulate_hybrid(
        &keys.share_x25519_seed,
        &keys.share_mlkem_seed,
        &eph,
        &env.mlkem_ciphertext,
        &transcript,
    )?;
    let content_key_bytes = aead::open(
        hybrid.as_bytes(),
        &env.wrap_nonce,
        &transcript,
        &env.wrapped_content_key,
    )?;
    let content_key: [u8; 32] = content_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let sender_vid = env.vault_id_bytes()?;
    let payload_aad =
        build_share_payload_transcript(&sender_vid, env.key_epoch, &env.share_id);
    let pt = aead::open(
        &content_key,
        &env.payload_nonce,
        &payload_aad,
        &env.payload_ciphertext,
    )?;
    ciborium::from_reader(pt.as_slice()).map_err(|e| CryptoError::Serde(e.to_string()))
}
