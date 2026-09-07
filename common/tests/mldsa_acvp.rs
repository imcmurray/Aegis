//! Official FIPS 204 ACVP ML-DSA-65 KATs against `ml-dsa` 0.1.1.
//!
//! Provenance: `tests/fixtures/acvp-mldsa65/PROVENANCE.md`.

use ml_dsa::{
    B32, EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes,
    MlDsa65, Signature, SigningKey, VerifyingKey,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/acvp-mldsa65")
}

fn hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("acvp hex")
}

fn sha256_file(name: &str) -> String {
    let bytes = std::fs::read(fixture_dir().join(name)).expect(name);
    hex::encode(Sha256::digest(&bytes))
}

fn load_json(name: &str) -> serde_json::Value {
    let bytes = std::fs::read(fixture_dir().join(name)).expect(name);
    serde_json::from_slice(&bytes).expect(name)
}

#[derive(Deserialize)]
struct VectorSet {
    algorithm: String,
    mode: String,
    revision: String,
    #[serde(rename = "vsId")]
    vs_id: u64,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(default)]
    deterministic: Option<bool>,
    #[serde(rename = "signatureInterface")]
    signature_interface: Option<String>,
    #[serde(rename = "preHash")]
    pre_hash: Option<String>,
    #[serde(rename = "externalMu", default)]
    external_mu: Option<bool>,
    tests: Vec<serde_json::Value>,
}

fn load_set(name: &str) -> VectorSet {
    serde_json::from_value(load_json(name)).expect(name)
}

fn esk_from_expanded(sk: &[u8]) -> ExpandedSigningKey<MlDsa65> {
    let enc = ExpandedSigningKeyBytes::<MlDsa65>::try_from(sk).expect("sk length");
    #[allow(deprecated)]
    ExpandedSigningKey::<MlDsa65>::from_expanded(&enc)
}

fn vk_from_pk(pk: &[u8]) -> VerifyingKey<MlDsa65> {
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pk).expect("pk length");
    VerifyingKey::<MlDsa65>::decode(&enc)
}

/// FIPS 204 Algorithm 2: M' = 0x00 || len(ctx) || ctx || M  (pure, not pre-hash).
fn external_m_prime(message: &[u8], ctx: &[u8]) -> Vec<u8> {
    assert!(ctx.len() <= 255);
    let mut m = Vec::with_capacity(2 + ctx.len() + message.len());
    m.push(0x00);
    m.push(ctx.len() as u8);
    m.extend_from_slice(ctx);
    m.extend_from_slice(message);
    m
}

#[test]
fn vendored_files_match_recorded_checksums() {
    let sums = std::fs::read_to_string(fixture_dir().join("SHA256SUMS")).unwrap();
    let mut n = 0;
    for line in sums.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let want = parts.next().unwrap();
        let name = parts.next().unwrap();
        assert_eq!(sha256_file(name), want, "{name}");
        n += 1;
    }
    assert_eq!(n, 3);
}

#[test]
fn acvp_keygen_mldsa65_matches_official_pk_and_expanded_sk() {
    let set = load_set("keyGen-FIPS204-ML-DSA-65.json");
    assert_eq!(set.algorithm, "ML-DSA");
    assert_eq!(set.mode, "keyGen");
    assert_eq!(set.revision, "FIPS204");
    assert_eq!(set.vs_id, 42);
    assert_eq!(set.test_groups.len(), 1);
    let g = &set.test_groups[0];
    assert_eq!(g.parameter_set, "ML-DSA-65");
    assert_eq!(g.tg_id, 2);
    assert_eq!(g.tests.len(), 25);

    for tc in &g.tests {
        let seed = hex_bytes(tc["seed"].as_str().unwrap());
        let pk = hex_bytes(tc["pk"].as_str().unwrap());
        let sk = hex_bytes(tc["sk"].as_str().unwrap());
        assert_eq!(seed.len(), 32);
        assert_eq!(pk.len(), 1952);
        assert_eq!(sk.len(), 4032);

        let seed_arr = B32::try_from(seed.as_slice()).unwrap();
        let ssk = SigningKey::<MlDsa65>::from_seed(&seed_arr);
        assert_eq!(ssk.as_ref().encode().as_slice(), pk.as_slice());
        #[allow(deprecated)]
        {
            assert_eq!(ssk.expanded_key().to_expanded().as_slice(), sk.as_slice());
        }
    }
}

#[test]
fn acvp_siggen_mldsa65_matches_official_signatures() {
    let set = load_set("sigGen-FIPS204-ML-DSA-65.json");
    assert_eq!(set.algorithm, "ML-DSA");
    assert_eq!(set.mode, "sigGen");
    assert_eq!(set.revision, "FIPS204");
    assert_eq!(set.vs_id, 42);
    assert_eq!(set.test_groups.len(), 4);

    let mut n = 0u32;
    for g in &set.test_groups {
        assert_eq!(g.parameter_set, "ML-DSA-65");
        assert_ne!(g.pre_hash.as_deref(), Some("preHash"));
        assert_ne!(g.external_mu, Some(true));
        let iface = g.signature_interface.as_deref().unwrap();
        let deterministic = g.deterministic.unwrap();

        for tc in &g.tests {
            let sk = hex_bytes(tc["sk"].as_str().unwrap());
            let pk = hex_bytes(tc["pk"].as_str().unwrap());
            let want = hex_bytes(tc["signature"].as_str().unwrap());
            let esk = esk_from_expanded(&sk);
            assert_eq!(esk.verifying_key().encode().as_slice(), pk.as_slice());

            let got = match (iface, deterministic) {
                ("external", true) => {
                    let msg = hex_bytes(tc["message"].as_str().unwrap());
                    let ctx = hex_bytes(tc["context"].as_str().unwrap());
                    esk.sign_deterministic(&msg, &ctx).expect("sign")
                }
                ("internal", true) => {
                    let msg = hex_bytes(tc["message"].as_str().unwrap());
                    esk.sign_internal(&[&msg], &B32::default())
                }
                ("external", false) => {
                    let msg = hex_bytes(tc["message"].as_str().unwrap());
                    let ctx = hex_bytes(tc["context"].as_str().unwrap());
                    let rnd = hex_bytes(tc["rnd"].as_str().unwrap());
                    let rnd = B32::try_from(rnd.as_slice()).unwrap();
                    let mp = external_m_prime(&msg, &ctx);
                    esk.sign_internal(&[&mp], &rnd)
                }
                ("internal", false) => {
                    let msg = hex_bytes(tc["message"].as_str().unwrap());
                    let rnd = hex_bytes(tc["rnd"].as_str().unwrap());
                    let rnd = B32::try_from(rnd.as_slice()).unwrap();
                    esk.sign_internal(&[&msg], &rnd)
                }
                other => panic!("unexpected group {other:?}"),
            };
            assert_eq!(got.encode().as_slice(), want.as_slice(), "tgId {}", g.tg_id);
            n += 1;
        }
    }
    assert_eq!(n, 60);
}

#[test]
fn acvp_sigver_mldsa65_accepts_and_rejects_official_cases() {
    let set = load_set("sigVer-FIPS204-ML-DSA-65.json");
    assert_eq!(set.algorithm, "ML-DSA");
    assert_eq!(set.mode, "sigVer");
    assert_eq!(set.revision, "FIPS204");
    assert_eq!(set.vs_id, 42);
    assert_eq!(set.test_groups.len(), 2);

    let mut n_pass = 0u32;
    let mut n_fail = 0u32;
    for g in &set.test_groups {
        assert_eq!(g.parameter_set, "ML-DSA-65");
        let iface = g.signature_interface.as_deref().unwrap();
        for tc in &g.tests {
            let pk = hex_bytes(tc["pk"].as_str().unwrap());
            let sig = hex_bytes(tc["signature"].as_str().unwrap());
            let want = tc["testPassed"].as_bool().unwrap();
            let vk = vk_from_pk(&pk);
            let ok = EncodedSignature::<MlDsa65>::try_from(sig.as_slice())
                .ok()
                .and_then(|enc| Signature::<MlDsa65>::decode(&enc))
                .map(|sigma| match iface {
                    "external" => {
                        let msg = hex_bytes(tc["message"].as_str().unwrap());
                        let ctx = hex_bytes(tc["context"].as_str().unwrap());
                        vk.verify_with_context(&msg, &ctx, &sigma)
                    }
                    "internal" => {
                        let msg = hex_bytes(tc["message"].as_str().unwrap());
                        vk.verify_internal(&msg, &sigma)
                    }
                    other => panic!("unexpected iface {other}"),
                })
                .unwrap_or(false);
            assert_eq!(
                ok, want,
                "tgId {} tcId {} reason {:?}",
                g.tg_id,
                tc["tcId"],
                tc.get("reason")
            );
            if want {
                n_pass += 1;
            } else {
                n_fail += 1;
            }
        }
    }
    assert_eq!(n_pass, 6);
    assert_eq!(n_fail, 24);
}
