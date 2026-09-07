//! Write valid v1/v2 objects into fuzz/corpus/* for dedicated campaigns.
//! Run: cargo run --manifest-path fuzz/Cargo.toml --bin seed_corpus

use aegis_common::crypto::{wrap_master, KdfProfile};
use aegis_common::messages::{VaultRequest, VaultResponse};
use aegis_common::session_v2::{VaultSessionV2, SECRET_ENVELOPE_V2, SECRET_VAULT_V2};
use aegis_common::sync_v2::{encode_state_v2_file, VaultSyncStateV2};
use aegis_common::types::Entry;
use aegis_common::vault::{dispatch, ActiveSession, MemoryStore, SecretStore};
use std::fs;
use std::path::PathBuf;

const PW: &str = "correct horse battery staple";

fn write(dir: &str, name: &str, bytes: &[u8]) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let d = root.join("corpus").join(dir);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join(name), bytes).unwrap();
    println!("seeded {}/{} ({} bytes)", dir, name, bytes.len());
}

fn main() {
    let mut store = MemoryStore::default();
    let mut s = VaultSessionV2::create(&mut store, PW).unwrap();
    let mut e = Entry::new("e1", "Mail");
    e.password = "inbox-secret".into();
    s.doc.entries.insert(e.id.clone(), e);
    s.persist(&mut store).unwrap();

    write(
        "master_envelope_v2",
        "valid.bin",
        &store.get(SECRET_ENVELOPE_V2).unwrap(),
    );
    write(
        "vault_blob_v2",
        "valid.bin",
        &store.get(SECRET_VAULT_V2).unwrap(),
    );

    let backup = s.export_backup(PW).unwrap();
    write("backup_envelope_v2", "valid.bin", &backup);

    let mut session = Some(ActiveSession::V2(s));
    match dispatch(
        &mut store,
        &mut session,
        VaultRequest::GenerateRecoveryKey { kdf_profile: None },
    ) {
        VaultResponse::RecoveryKey { kit, .. } => write("recovery_kit_v2", "valid.bin", &kit),
        other => panic!("{other:?}"),
    }

    let ident = match dispatch(&mut store, &mut session, VaultRequest::ExportShareIdentity) {
        VaultResponse::ShareIdentity { blob } => blob,
        other => panic!("{other:?}"),
    };
    match dispatch(
        &mut store,
        &mut session,
        VaultRequest::CreateShare {
            entry_id: "e1".into(),
            recipient_identity: ident,
        },
    ) {
        VaultResponse::ShareEnvelope { blob } => {
            write("share_envelope_v2", "valid.bin", &blob)
        }
        other => panic!("{other:?}"),
    }

    write(
        "sync_state_v2",
        "empty.bin",
        &encode_state_v2_file(&VaultSyncStateV2::default()).unwrap(),
    );

    let (env, _) = wrap_master(PW, KdfProfile::Test, "fixture-vault").unwrap();
    write("v1_master_envelope", "generated.cbor", &env.to_cbor().unwrap());

    let v1_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../common/tests/fixtures/v1");
    if let Ok(rd) = fs::read_dir(&v1_dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if p.extension().and_then(|e| e.to_str()) == Some("cbor") {
                if let Ok(bytes) = fs::read(&p) {
                    write("v1_master_envelope", name.as_ref(), &bytes);
                }
            }
        }
    }
}
