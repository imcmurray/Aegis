//! Official FIPS 203 ACVP ML-KEM-768 KATs against `ml-kem` 0.3.2.
//!
//! Provenance: `tests/fixtures/acvp-mlkem768/PROVENANCE.md`.

use ml_kem::kem::{Decapsulate, KeyExport, TryKeyInit};
use ml_kem::{
    B32, Ciphertext, DecapsulationKey, EncapsulationKey, ExpandedDecapsulationKey, MlKem768,
    Seed,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/acvp-mlkem768")
}

fn hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("acvp hex")
}

fn sha256_file(name: &str) -> String {
    let bytes = std::fs::read(fixture_dir().join(name)).expect(name);
    hex::encode(Sha256::digest(&bytes))
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
    function: Option<String>,
    tests: Vec<serde_json::Value>,
}

fn load_set(name: &str) -> VectorSet {
    let bytes = std::fs::read(fixture_dir().join(name)).expect(name);
    serde_json::from_slice(&bytes).expect(name)
}

#[test]
fn vendored_mlkem_files_match_recorded_checksums() {
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
    assert_eq!(n, 2);
}

#[test]
fn acvp_keygen_mlkem768_matches_official_ek() {
    let set = load_set("keyGen-FIPS203-ML-KEM-768.json");
    assert_eq!(set.algorithm, "ML-KEM");
    assert_eq!(set.mode, "keyGen");
    assert_eq!(set.revision, "FIPS203");
    assert_eq!(set.vs_id, 42);
    assert_eq!(set.test_groups.len(), 1);
    let g = &set.test_groups[0];
    assert_eq!(g.parameter_set, "ML-KEM-768");
    assert_eq!(g.tg_id, 2);
    assert_eq!(g.tests.len(), 25);

    for tc in &g.tests {
        let d = hex_bytes(tc["d"].as_str().unwrap());
        let z = hex_bytes(tc["z"].as_str().unwrap());
        let ek = hex_bytes(tc["ek"].as_str().unwrap());
        assert_eq!(d.len(), 32);
        assert_eq!(z.len(), 32);
        assert_eq!(ek.len(), 1184);
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);
        let seed = Seed::from(seed);
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        assert_eq!(dk.encapsulation_key().to_bytes().as_slice(), ek.as_slice());
    }
}

#[test]
fn acvp_encapdecap_mlkem768_matches_official_c_and_k() {
    let set = load_set("encapDecap-FIPS203-ML-KEM-768.json");
    assert_eq!(set.algorithm, "ML-KEM");
    assert_eq!(set.mode, "encapDecap");
    assert_eq!(set.revision, "FIPS203");
    assert_eq!(set.vs_id, 42);
    assert_eq!(set.test_groups.len(), 2);

    let mut n_encap = 0u32;
    let mut n_decap = 0u32;
    for g in &set.test_groups {
        assert_eq!(g.parameter_set, "ML-KEM-768");
        match g.function.as_deref() {
            Some("encapsulation") => {
                assert_eq!(g.tg_id, 2);
                for tc in &g.tests {
                    let ek = hex_bytes(tc["ek"].as_str().unwrap());
                    let m = hex_bytes(tc["m"].as_str().unwrap());
                    let want_c = hex_bytes(tc["c"].as_str().unwrap());
                    let want_k = hex_bytes(tc["k"].as_str().unwrap());
                    let ek = EncapsulationKey::<MlKem768>::new_from_slice(&ek).unwrap();
                    let m = B32::try_from(m.as_slice()).unwrap();
                    let (c, k) = ek.encapsulate_deterministic(&m);
                    assert_eq!(c.as_slice(), want_c.as_slice(), "tcId {}", tc["tcId"]);
                    assert_eq!(k.as_slice(), want_k.as_slice(), "tcId {}", tc["tcId"]);
                    n_encap += 1;
                }
            }
            Some("decapsulation") => {
                assert_eq!(g.tg_id, 5);
                for tc in &g.tests {
                    let dk = hex_bytes(tc["dk"].as_str().unwrap());
                    let c = hex_bytes(tc["c"].as_str().unwrap());
                    let want_k = hex_bytes(tc["k"].as_str().unwrap());
                    let enc = ExpandedDecapsulationKey::<MlKem768>::try_from(dk.as_slice())
                        .expect("dk length");
                    #[allow(deprecated)]
                    let dk = DecapsulationKey::<MlKem768>::from_expanded(&enc).unwrap();
                    let ct = Ciphertext::<MlKem768>::try_from(c.as_slice()).unwrap();
                    let k = dk.decapsulate(&ct);
                    assert_eq!(k.as_slice(), want_k.as_slice(), "tcId {}", tc["tcId"]);
                    n_decap += 1;
                }
            }
            other => panic!("unexpected function {other:?}"),
        }
    }
    assert_eq!(n_encap, 25);
    assert_eq!(n_decap, 10);
}
