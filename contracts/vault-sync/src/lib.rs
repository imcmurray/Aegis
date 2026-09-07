//! VaultSync contract: stores only encrypted vault revisions.
//!
//! v1: Ed25519 over `EncryptedRevision` (`AEGIS_VAULT_SYNC_V1`).
//! v2: Ed25519 AND ML-DSA-65 over `EncryptedRevisionV2` (`AEGIS_VAULT_SYNC_V2`).
//! Hybrid objects never fall back to the v1 decoder.

#![allow(dead_code)]

use aegis_common::sync::revision_sign_bytes;
use aegis_common::sync_types::{
    decode_cbor, encode_cbor, EncryptedRevision, VaultSyncParams, VaultSyncState,
};
use aegis_common::sync_v2::{
    verify_revision_against_params, verify_transition_v2, EncryptedRevisionV2, VaultSyncParamsV2,
    VaultSyncStateV2, APP_VAULT_SYNC_V2,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use freenet_stdlib::prelude::*;
use serde::Deserialize;

struct Contract;

const APP_V1: &str = "AEGIS_VAULT_SYNC_V1";

#[derive(Deserialize)]
struct AppPeek {
    #[serde(default)]
    app: String,
}

fn peek_app(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    decode_cbor::<AppPeek>(bytes)
        .map(|p| p.app)
        .unwrap_or_default()
}

fn is_v2_app(app: &str) -> bool {
    app == APP_VAULT_SYNC_V2
}

fn load_params_v1(parameters: &Parameters<'_>) -> Result<VaultSyncParams, ContractError> {
    if parameters.as_ref().is_empty() {
        return Ok(VaultSyncParams::default());
    }
    decode_cbor(parameters.as_ref()).map_err(ContractError::Deser)
}

fn load_params_v2(parameters: &Parameters<'_>) -> Result<VaultSyncParamsV2, ContractError> {
    if parameters.as_ref().is_empty() {
        return Err(ContractError::InvalidState);
    }
    let params: VaultSyncParamsV2 =
        decode_cbor(parameters.as_ref()).map_err(ContractError::Deser)?;
    params
        .validate()
        .map_err(|_| ContractError::InvalidState)?;
    Ok(params)
}

fn load_state_v1(state: &State<'_>) -> Result<VaultSyncState, ContractError> {
    if state.as_ref().is_empty() {
        return Ok(VaultSyncState::default());
    }
    decode_cbor(state.as_ref()).map_err(ContractError::Deser)
}

fn load_state_v2(state: &State<'_>) -> Result<VaultSyncStateV2, ContractError> {
    if state.as_ref().is_empty() {
        return Ok(VaultSyncStateV2::default());
    }
    decode_cbor(state.as_ref()).map_err(ContractError::Deser)
}

fn dump_state_v1(state: &VaultSyncState) -> Result<Vec<u8>, ContractError> {
    encode_cbor(state).map_err(ContractError::Deser)
}

fn dump_state_v2(state: &VaultSyncStateV2) -> Result<Vec<u8>, ContractError> {
    aegis_common::sync_v2::encode_cbor(state).map_err(ContractError::Deser)
}

fn verify_revision_v1(
    params: &VaultSyncParams,
    rev: &EncryptedRevision,
) -> Result<(), ContractError> {
    if params.owner_verifying_key.len() != 32 {
        return Err(ContractError::InvalidState);
    }
    if rev.ciphertext.len() > VaultSyncState::MAX_CIPHERTEXT {
        return Err(ContractError::InvalidUpdate);
    }
    if rev.signature.len() != 64 {
        return Err(ContractError::InvalidUpdate);
    }

    let mut vk_bytes = [0u8; 32];
    vk_bytes.copy_from_slice(&params.owner_verifying_key);
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| ContractError::InvalidState)?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&rev.signature);
    let sig = Signature::from_bytes(&sig_bytes);

    let msg = revision_sign_bytes(rev);
    vk.verify(&msg, &sig)
        .map_err(|_| ContractError::InvalidUpdate)?;
    Ok(())
}

fn validate_state_v1(
    params: &VaultSyncParams,
    state: &VaultSyncState,
) -> Result<(), ContractError> {
    if is_v2_app(&params.app) {
        return Err(ContractError::InvalidState);
    }
    if params.app != APP_V1 && !params.app.is_empty() {
        if !params.owner_verifying_key.is_empty() && params.app != APP_V1 {
            return Err(ContractError::InvalidState);
        }
    }
    if state.revisions.len() > VaultSyncState::MAX_REVISIONS {
        return Err(ContractError::InvalidState);
    }
    for rev in &state.revisions {
        if !params.owner_verifying_key.is_empty() {
            verify_revision_v1(params, rev)?;
        }
    }
    Ok(())
}

fn validate_state_v2(
    params: &VaultSyncParamsV2,
    state: &VaultSyncStateV2,
) -> Result<(), ContractError> {
    params
        .validate()
        .map_err(|_| ContractError::InvalidState)?;
    if state.revisions.len() > VaultSyncStateV2::MAX_REVISIONS {
        return Err(ContractError::InvalidState);
    }
    if state.transitions.len() > VaultSyncStateV2::MAX_TRANSITIONS {
        return Err(ContractError::InvalidState);
    }
    for t in &state.transitions {
        verify_transition_v2(t).map_err(|_| ContractError::InvalidUpdate)?;
        if t.new_identity.ed25519_vk != params.ed25519_verifying_key
            || t.new_identity.ml_dsa_vk != params.ml_dsa_verifying_key
        {
            // Transition must land on the params identity (current epoch).
            if t.old_identity.ed25519_vk != params.ed25519_verifying_key
                || t.old_identity.ml_dsa_vk != params.ml_dsa_verifying_key
            {
                return Err(ContractError::InvalidUpdate);
            }
        }
    }
    for rev in &state.revisions {
        verify_revision_against_params(params, rev).map_err(|_| ContractError::InvalidUpdate)?;
    }
    Ok(())
}

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let app = peek_app(parameters.as_ref());
        if is_v2_app(&app) {
            let params = load_params_v2(&parameters)?;
            let st = load_state_v2(&state)?;
            validate_state_v2(&params, &st)?;
            return Ok(ValidateResult::Valid);
        }
        let params = load_params_v1(&parameters)?;
        let st = load_state_v1(&state)?;
        validate_state_v1(&params, &st)?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let app = peek_app(parameters.as_ref());
        if is_v2_app(&app) {
            return update_state_v2(parameters, state, data);
        }
        update_state_v1(parameters, state, data)
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let app = peek_app(parameters.as_ref());
        if is_v2_app(&app) {
            let st = load_state_v2(&state)?;
            let summary: Vec<(String, u32, u64, [u8; 32])> = st
                .revisions
                .iter()
                .map(|r| (r.device_id.clone(), r.key_epoch, r.counter, r.ciphertext_hash))
                .collect();
            let bytes = encode_cbor(&summary).map_err(ContractError::Deser)?;
            return Ok(StateSummary::from(bytes));
        }
        let st = load_state_v1(&state)?;
        let summary: Vec<(String, Vec<(String, u64)>, [u8; 32])> = st
            .revisions
            .iter()
            .map(|r| {
                (
                    r.device_id.clone(),
                    r.version_vector.0.iter().map(|(k, v)| (k.clone(), *v)).collect(),
                    r.content_hash,
                )
            })
            .collect();
        let bytes = encode_cbor(&summary).map_err(ContractError::Deser)?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let app = peek_app(parameters.as_ref());
        if is_v2_app(&app) {
            let st = load_state_v2(&state)?;
            if summary.as_ref().is_empty() {
                let bytes = dump_state_v2(&st)?;
                return Ok(StateDelta::from(bytes));
            }
            let known: Vec<(String, u32, u64, [u8; 32])> =
                decode_cbor(summary.as_ref()).map_err(ContractError::Deser)?;
            let known_hashes: std::collections::BTreeSet<[u8; 32]> =
                known.into_iter().map(|(_, _, _, h)| h).collect();
            let mut delta = VaultSyncStateV2::default();
            for rev in st.revisions {
                if !known_hashes.contains(&rev.ciphertext_hash) {
                    delta.revisions.push(rev);
                }
            }
            let bytes = dump_state_v2(&delta)?;
            return Ok(StateDelta::from(bytes));
        }
        let st = load_state_v1(&state)?;
        if summary.as_ref().is_empty() {
            let bytes = dump_state_v1(&st)?;
            return Ok(StateDelta::from(bytes));
        }
        let known: Vec<(String, Vec<(String, u64)>, [u8; 32])> =
            decode_cbor(summary.as_ref()).map_err(ContractError::Deser)?;
        let known_hashes: std::collections::BTreeSet<[u8; 32]> =
            known.into_iter().map(|(_, _, h)| h).collect();

        let mut delta = VaultSyncState::default();
        for rev in st.revisions {
            if !known_hashes.contains(&rev.content_hash) {
                delta.revisions.push(rev);
            }
        }
        let bytes = dump_state_v1(&delta)?;
        Ok(StateDelta::from(bytes))
    }
}

fn update_state_v1(
    parameters: Parameters<'static>,
    state: State<'static>,
    data: Vec<UpdateData<'static>>,
) -> Result<UpdateModification<'static>, ContractError> {
    let params = load_params_v1(&parameters)?;
    let mut st = load_state_v1(&state)?;

    for update in data {
        match update {
            UpdateData::State(new_state) => {
                let incoming = load_state_v1(&new_state)?;
                validate_state_v1(&params, &incoming)?;
                st.merge(&incoming);
            }
            UpdateData::Delta(delta) => {
                if let Ok(rev) = decode_cbor::<EncryptedRevision>(delta.as_ref()) {
                    if !params.owner_verifying_key.is_empty() {
                        verify_revision_v1(&params, &rev)?;
                    }
                    st.upsert(rev);
                } else if let Ok(incoming) = decode_cbor::<VaultSyncState>(delta.as_ref()) {
                    validate_state_v1(&params, &incoming)?;
                    st.merge(&incoming);
                } else {
                    return Err(ContractError::Deser("invalid delta".into()));
                }
            }
            _ => {}
        }
    }

    validate_state_v1(&params, &st)?;
    let out = dump_state_v1(&st)?;
    Ok(UpdateModification::valid(out.into()))
}

fn update_state_v2(
    parameters: Parameters<'static>,
    state: State<'static>,
    data: Vec<UpdateData<'static>>,
) -> Result<UpdateModification<'static>, ContractError> {
    let params = load_params_v2(&parameters)?;
    let mut st = load_state_v2(&state)?;

    for update in data {
        match update {
            UpdateData::State(new_state) => {
                let incoming = load_state_v2(&new_state)?;
                validate_state_v2(&params, &incoming)?;
                st.merge(&incoming);
            }
            UpdateData::Delta(delta) => {
                if decode_cbor::<EncryptedRevision>(delta.as_ref()).is_ok() {
                    // v1 revision must never enter a v2 instance.
                    return Err(ContractError::InvalidUpdate);
                }
                if let Ok(rev) = decode_cbor::<EncryptedRevisionV2>(delta.as_ref()) {
                    verify_revision_against_params(&params, &rev)
                        .map_err(|_| ContractError::InvalidUpdate)?;
                    st.upsert(rev);
                } else if let Ok(incoming) = decode_cbor::<VaultSyncStateV2>(delta.as_ref()) {
                    validate_state_v2(&params, &incoming)?;
                    st.merge(&incoming);
                } else {
                    return Err(ContractError::Deser("invalid delta".into()));
                }
            }
            _ => {}
        }
    }

    validate_state_v2(&params, &st)?;
    let out = dump_state_v2(&st)?;
    Ok(UpdateModification::valid(out.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::crdt::VersionVector;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_rev(sk: &SigningKey, device: &str, n: u64, ct: &[u8]) -> EncryptedRevision {
        let mut vv = VersionVector::new();
        for _ in 0..n {
            vv.increment(device);
        }
        let content_hash = {
            let mut h = [0u8; 32];
            h.copy_from_slice(blake3::hash(ct).as_bytes());
            h
        };
        let mut rev = EncryptedRevision {
            version_vector: vv,
            device_id: device.into(),
            signature: vec![],
            ciphertext: ct.to_vec(),
            content_hash,
        };
        let msg = revision_sign_bytes(&rev);
        let sig = sk.sign(&msg);
        rev.signature = sig.to_bytes().to_vec();
        rev
    }

    #[test]
    fn merge_concurrent_revisions() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let params = VaultSyncParams {
            owner_verifying_key: vk.as_bytes().to_vec(),
            app: APP_V1.into(),
        };

        let r1 = signed_rev(&sk, "d1", 1, b"cipher-a");
        let r2 = signed_rev(&sk, "d2", 1, b"cipher-b");

        let mut a = VaultSyncState {
            revisions: vec![r1.clone()],
        };
        let b = VaultSyncState {
            revisions: vec![r2.clone()],
        };
        a.merge(&b);
        assert_eq!(a.revisions.len(), 2);

        let params_bytes = encode_cbor(&params).unwrap();
        let state_bytes = encode_cbor(&a).unwrap();
        let result = <Contract as ContractInterface>::validate_state(
            Parameters::from(params_bytes),
            State::from(state_bytes),
            RelatedContracts::default(),
        )
        .unwrap();
        assert!(matches!(result, ValidateResult::Valid));
    }

    #[test]
    fn v2_params_do_not_validate_v1_state() {
        let params = VaultSyncParamsV2 {
            ed25519_verifying_key: vec![1u8; 32],
            ml_dsa_verifying_key: vec![2u8; 1952],
            app: APP_VAULT_SYNC_V2.into(),
        };
        // A non-empty v1 revision must fail closed on a v2 instance.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut filled = VaultSyncState::default();
        filled.revisions.push(signed_rev(&sk, "d1", 1, b"ct"));
        let result = <Contract as ContractInterface>::validate_state(
            Parameters::from(encode_cbor(&params).unwrap()),
            State::from(encode_cbor(&filled).unwrap()),
            RelatedContracts::default(),
        );
        assert!(result.is_err(), "{result:?}");
        let _ = result;
    }
}
