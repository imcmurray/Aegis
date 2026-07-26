//! VaultSync contract: stores only encrypted vault revisions.
//!
//! Merge is commutative over cleartext version vectors. Ciphertext is opaque.
//! Writes must be signed by the owner verifying key in contract parameters.

// Helpers are referenced from the #[contract] impl; rustc can miss that linkage
// without freenet-main-contract WASM exports on native builds.
#![allow(dead_code)]

use aegis_common::sync::revision_sign_bytes;
use aegis_common::sync_types::{
    decode_cbor, encode_cbor, EncryptedRevision, VaultSyncParams, VaultSyncState,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use freenet_stdlib::prelude::*;

struct Contract;

fn load_params(parameters: &Parameters<'_>) -> Result<VaultSyncParams, ContractError> {
    if parameters.as_ref().is_empty() {
        return Ok(VaultSyncParams::default());
    }
    decode_cbor(parameters.as_ref()).map_err(|e| ContractError::Deser(e))
}

fn load_state(state: &State<'_>) -> Result<VaultSyncState, ContractError> {
    if state.as_ref().is_empty() {
        return Ok(VaultSyncState::default());
    }
    decode_cbor(state.as_ref()).map_err(|e| ContractError::Deser(e))
}

fn dump_state(state: &VaultSyncState) -> Result<Vec<u8>, ContractError> {
    encode_cbor(state).map_err(|e| ContractError::Deser(e))
}

fn verify_revision(params: &VaultSyncParams, rev: &EncryptedRevision) -> Result<(), ContractError> {
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

fn validate_state_inner(
    params: &VaultSyncParams,
    state: &VaultSyncState,
) -> Result<(), ContractError> {
    if params.app != "AEGIS_VAULT_SYNC_V1" && !params.app.is_empty() {
        // Allow empty during bootstrap; once set must match.
        if !params.owner_verifying_key.is_empty() && params.app != "AEGIS_VAULT_SYNC_V1" {
            return Err(ContractError::InvalidState);
        }
    }
    if state.revisions.len() > VaultSyncState::MAX_REVISIONS {
        return Err(ContractError::InvalidState);
    }
    for rev in &state.revisions {
        if !params.owner_verifying_key.is_empty() {
            verify_revision(params, rev)?;
        }
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
        let params = load_params(&parameters)?;
        let st = load_state(&state)?;
        validate_state_inner(&params, &st)?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = load_params(&parameters)?;
        let mut st = load_state(&state)?;

        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    let incoming = load_state(&new_state)?;
                    validate_state_inner(&params, &incoming)?;
                    st.merge(&incoming);
                }
                UpdateData::Delta(delta) => {
                    // Delta is a single EncryptedRevision or a VaultSyncState.
                    if let Ok(rev) = decode_cbor::<EncryptedRevision>(delta.as_ref()) {
                        if !params.owner_verifying_key.is_empty() {
                            verify_revision(&params, &rev)?;
                        }
                        st.upsert(rev);
                    } else if let Ok(incoming) = decode_cbor::<VaultSyncState>(delta.as_ref()) {
                        validate_state_inner(&params, &incoming)?;
                        st.merge(&incoming);
                    } else {
                        return Err(ContractError::Deser("invalid delta".into()));
                    }
                }
                _ => {}
            }
        }

        validate_state_inner(&params, &st)?;
        let out = dump_state(&st)?;
        Ok(UpdateModification::valid(out.into()))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let st = load_state(&state)?;
        // Summary: list of (device_id, vv, content_hash) without ciphertext.
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
        let bytes = encode_cbor(&summary).map_err(|e| ContractError::Deser(e))?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let st = load_state(&state)?;
        if summary.as_ref().is_empty() {
            let bytes = dump_state(&st)?;
            return Ok(StateDelta::from(bytes));
        }
        let known: Vec<(String, Vec<(String, u64)>, [u8; 32])> =
            decode_cbor(summary.as_ref()).map_err(|e| ContractError::Deser(e))?;
        let known_hashes: std::collections::BTreeSet<[u8; 32]> =
            known.into_iter().map(|(_, _, h)| h).collect();

        let mut delta = VaultSyncState::default();
        for rev in st.revisions {
            if !known_hashes.contains(&rev.content_hash) {
                delta.revisions.push(rev);
            }
        }
        let bytes = dump_state(&delta)?;
        Ok(StateDelta::from(bytes))
    }
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
            app: "AEGIS_VAULT_SYNC_V1".into(),
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
}
