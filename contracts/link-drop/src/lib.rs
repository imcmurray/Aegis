//! Link-drop contract (D21): a one-time mailbox located by a link code.
//!
//! The contract parameters carry an Ed25519 verifying key derived from the
//! link code (`AEGIS_LINK_V1`). The state is one `LinkDropState`
//! (`offer` -> `ack` -> `tombstone`) signed by that key. Updates merge to the
//! maximum under `(seq, kind_rank, body, sig)`, which is commutative,
//! associative and idempotent. The contract never sees plaintext: the offer
//! body is sealed under a key that only the code holder can derive.

#![allow(dead_code)]

use aegis_common::link::{merge_link_states, verify_link_state, LinkDropState, MAX_LINK_STATE};
use freenet_stdlib::prelude::*;

struct Contract;

/// Decode and fully verify a non-empty encoded state.
fn decode_verified(params: &[u8], bytes: &[u8]) -> Result<LinkDropState, ContractError> {
    if bytes.len() > MAX_LINK_STATE {
        return Err(ContractError::InvalidUpdate);
    }
    let st = LinkDropState::from_cbor(bytes)
        .map_err(|_| ContractError::Deser("invalid link state".into()))?;
    verify_link_state(params, &st).map_err(|_| ContractError::InvalidUpdate)?;
    Ok(st)
}

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(ValidateResult::Valid);
        }
        if aegis_common::link::LinkDropParams::from_cbor(parameters.as_ref()).is_err() {
            return Err(ContractError::InvalidState);
        }
        decode_verified(parameters.as_ref(), state.as_ref())
            .map_err(|_| ContractError::InvalidState)?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = parameters.as_ref();
        let mut current: Option<LinkDropState> = if state.as_ref().is_empty() {
            None
        } else {
            Some(decode_verified(params, state.as_ref())?)
        };
        for update in data {
            let bytes: &[u8] = match &update {
                UpdateData::State(s) => s.as_ref(),
                UpdateData::Delta(d) => d.as_ref(),
                _ => continue,
            };
            if bytes.is_empty() {
                continue;
            }
            let incoming = decode_verified(params, bytes)?;
            current = Some(match current.take() {
                Some(cur) => merge_link_states(&cur, &incoming),
                None => incoming,
            });
        }
        let out = current.map(|s| s.to_cbor()).unwrap_or_default();
        Ok(UpdateModification::valid(out.into()))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(Vec::new()));
        }
        Ok(StateSummary::from(
            blake3::hash(state.as_ref()).as_bytes().to_vec(),
        ))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        _summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        Ok(StateDelta::from(state.as_ref().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::link::{
        derive_link_keys, sign_link_state, LinkDropParams, LinkKeys, LinkSecret, KIND_ACK,
        KIND_OFFER, KIND_TOMBSTONE, MAX_LINK_SEALED, MAX_LINK_SMALL_BODY,
    };

    fn keys(n: u8) -> (LinkKeys, Vec<u8>) {
        let k = derive_link_keys(&LinkSecret::from_bytes([n; 20]));
        let p = LinkDropParams::from_keys(&k).to_cbor();
        (k, p)
    }

    fn st(k: &LinkKeys, p: &[u8], seq: u64, kind: &str, body: &[u8]) -> Vec<u8> {
        sign_link_state(k, p, seq, kind, body.to_vec()).to_cbor()
    }

    fn validate(p: &[u8], s: &[u8]) -> Result<ValidateResult, ContractError> {
        <Contract as ContractInterface>::validate_state(
            Parameters::from(p.to_vec()),
            State::from(s.to_vec()),
            RelatedContracts::default(),
        )
    }

    fn update(p: &[u8], cur: &[u8], incoming: &[&[u8]]) -> Result<Vec<u8>, ContractError> {
        let data = incoming
            .iter()
            .map(|b| UpdateData::State(State::from(b.to_vec())))
            .collect();
        let m = <Contract as ContractInterface>::update_state(
            Parameters::from(p.to_vec()),
            State::from(cur.to_vec()),
            data,
        )?;
        Ok(m.unwrap_valid().as_ref().to_vec())
    }

    fn fixed_states(k: &LinkKeys, p: &[u8]) -> Vec<Vec<u8>> {
        vec![
            st(k, p, 1, KIND_OFFER, b"offer-a"),
            st(k, p, 1, KIND_OFFER, b"offer-b"),
            st(k, p, 2, KIND_ACK, b"ack-a"),
            st(k, p, 2, KIND_ACK, b"ack-b"),
            st(k, p, 3, KIND_TOMBSTONE, b""),
            st(k, p, 1, KIND_TOMBSTONE, b""),
            st(k, p, 2, KIND_OFFER, b"offer-hi"),
            st(k, p, 3, KIND_ACK, b"ack-3"),
        ]
    }

    #[test]
    fn valid_states_and_empty() {
        let (k, p) = keys(1);
        for s in [
            st(&k, &p, 1, KIND_OFFER, b"sealed"),
            st(&k, &p, 2, KIND_ACK, b"ack"),
            st(&k, &p, 3, KIND_TOMBSTONE, b""),
        ] {
            assert!(matches!(validate(&p, &s), Ok(ValidateResult::Valid)));
        }
        assert!(matches!(validate(&p, &[]), Ok(ValidateResult::Valid)));
    }

    #[test]
    fn invalid_states_are_rejected() {
        let (k, p) = keys(1);
        let (other, _) = keys(2);
        assert!(validate(&p, &st(&other, &p, 1, KIND_OFFER, b"x")).is_err());
        let mut flipped = aegis_common::link::LinkDropState::from_cbor(&st(&k, &p, 1, KIND_OFFER, b"x")).unwrap();
        flipped.sig[0] ^= 1;
        assert!(validate(&p, &flipped.to_cbor()).is_err());
        assert!(validate(&p, &st(&k, &p, 1, "weird", b"x")).is_err());
        assert!(validate(&p, &st(&k, &p, 1, KIND_OFFER, &vec![0u8; MAX_LINK_SEALED + 1])).is_err());
        assert!(validate(&p, &st(&k, &p, 2, KIND_ACK, &vec![0u8; MAX_LINK_SMALL_BODY + 1])).is_err());
        assert!(validate(&p, &st(&k, &p, 3, KIND_TOMBSTONE, &vec![0u8; MAX_LINK_SMALL_BODY + 1])).is_err());
        let bad_params = LinkDropParams {
            app: "WRONG".into(),
            ed25519_vk: k.verifying_key_bytes().to_vec(),
        }
        .to_cbor();
        let s = st(&k, &bad_params, 1, KIND_OFFER, b"x");
        assert!(validate(&bad_params, &s).is_err());
    }

    #[test]
    fn merge_precedence() {
        let (k, p) = keys(3);
        let offer = st(&k, &p, 1, KIND_OFFER, b"o");
        let ack = st(&k, &p, 1, KIND_ACK, b"a");
        let tomb = st(&k, &p, 1, KIND_TOMBSTONE, b"");
        assert_eq!(update(&p, &offer, &[&ack]).unwrap(), ack);
        assert_eq!(update(&p, &ack, &[&offer]).unwrap(), ack);
        assert_eq!(update(&p, &ack, &[&tomb]).unwrap(), tomb);
        let hi_offer = st(&k, &p, 2, KIND_OFFER, b"o");
        assert_eq!(update(&p, &tomb, &[&hi_offer]).unwrap(), hi_offer);
        // From nothing.
        assert_eq!(update(&p, &[], &[&offer]).unwrap(), offer);
        // No state, no data -> empty.
        assert!(update(&p, &[], &[]).unwrap().is_empty());
    }

    #[test]
    fn update_rejects_invalid_incoming() {
        let (k, p) = keys(4);
        let (other, _) = keys(5);
        let good = st(&k, &p, 1, KIND_OFFER, b"o");
        let bad = st(&other, &p, 2, KIND_ACK, b"a");
        assert!(update(&p, &good, &[&bad]).is_err());
        assert!(update(&p, &good, &[b"not cbor"]).is_err());
        // Delta path too.
        let r = <Contract as ContractInterface>::update_state(
            Parameters::from(p.clone()),
            State::from(good.clone()),
            vec![UpdateData::Delta(StateDelta::from(bad.clone()))],
        );
        assert!(r.is_err());
        // Empty deltas and states are ignored.
        let r = <Contract as ContractInterface>::update_state(
            Parameters::from(p.clone()),
            State::from(good.clone()),
            vec![UpdateData::Delta(StateDelta::from(Vec::new()))],
        )
        .unwrap();
        assert_eq!(r.unwrap_valid().as_ref(), good.as_slice());
    }

    #[test]
    fn update_is_commutative_associative_idempotent() {
        let (k, p) = keys(6);
        let all = fixed_states(&k, &p);
        assert!(all.len() >= 8);
        let merge2 = |a: &[u8], b: &[u8]| update(&p, a, &[b]).unwrap();
        for a in &all {
            assert_eq!(merge2(a, a), *a, "idempotent");
            for b in &all {
                assert_eq!(merge2(a, b), merge2(b, a), "commutative");
                for c in &all {
                    let left = merge2(&merge2(a, b), c);
                    let right = merge2(a, &merge2(b, c));
                    assert_eq!(left, right, "associative");
                    // Folding several updates at once agrees as well.
                    assert_eq!(update(&p, a, &[b, c]).unwrap(), left);
                }
            }
        }
    }

    #[test]
    fn summary_and_delta() {
        let (k, p) = keys(7);
        let s = st(&k, &p, 1, KIND_OFFER, b"o");
        let sum = <Contract as ContractInterface>::summarize_state(
            Parameters::from(p.clone()),
            State::from(s.clone()),
        )
        .unwrap();
        assert_eq!(sum.as_ref(), blake3::hash(&s).as_bytes().as_slice());
        let empty = <Contract as ContractInterface>::summarize_state(
            Parameters::from(p.clone()),
            State::from(Vec::new()),
        )
        .unwrap();
        assert!(empty.as_ref().is_empty());
        let d = <Contract as ContractInterface>::get_state_delta(
            Parameters::from(p),
            State::from(s.clone()),
            StateSummary::from(Vec::new()),
        )
        .unwrap();
        assert_eq!(d.as_ref(), s.as_slice());
    }
}
