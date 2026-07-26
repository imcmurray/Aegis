//! Print blake3 / base58 of a WASM file as JSON for Freenet delegate registration.

use serde::Serialize;
use std::env;
use std::fs;
use std::process;

#[derive(Serialize)]
struct HashOut {
    path: String,
    size: usize,
    /// blake3(wasm_bytes) — Freenet code hash
    blake3_hex: String,
    code_hash_b58: String,
    code_hash_bytes: Vec<u8>,
    /// blake3(code_hash || parameters) with empty parameters — instance key
    instance_key_b58: String,
    instance_key_bytes: Vec<u8>,
}

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: aegis-wasm-hash <file.wasm>");
        process::exit(2);
    });
    let data = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("read {path}: {e}");
        process::exit(1);
    });

    // Code hash = blake3 of WASM bytes (matches freenet-stdlib CodeHash::from_code)
    let code_hash = blake3::hash(&data);
    let code_bytes = code_hash.as_bytes().to_vec();

    // Instance key with empty parameters (matches freenet-stdlib generate_id):
    //   blake3(code_hash_bytes || parameters)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&code_bytes);
    hasher.update(&[]); // empty Parameters
    let instance = hasher.finalize();
    let instance_bytes = instance.as_bytes().to_vec();

    let out = HashOut {
        path,
        size: data.len(),
        blake3_hex: hex_encode(&code_bytes),
        code_hash_b58: b58(&code_bytes),
        code_hash_bytes: code_bytes,
        instance_key_b58: b58(&instance_bytes),
        instance_key_bytes: instance_bytes,
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn b58(b: &[u8]) -> String {
    bs58::encode(b)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string()
}
