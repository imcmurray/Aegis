//! Phase 10 / PR L: parser smoke, D14 persist hardening, adversarial parsers.

use crate::crypto::backup::{authenticate_backup, BackupEnvelopeV2, MAX_BACKUP_FILE};
use crate::crypto::envelope_v2::{
    MasterEnvelopeV2, VaultBlobV2, MAX_VAULT_FILE,
};
use crate::crypto::kdf::Argon2ParamsV2;
use crate::crypto::{
    CryptoError, MAGIC_BACKUP_V2, MAGIC_RECOVERY_V2, MAGIC_SYNC_V2, MAGIC_VAULT_V2, MasterEnvelope,
};
use crate::messages::{VaultRequest, VaultResponse};
use crate::recovery_v2::RecoveryWrapV2;
use crate::session_v2::{VaultSessionV2, SECRET_ENVELOPE_V2, SECRET_VAULT_V2};
use crate::share::ShareEnvelopeV2;
use crate::sync_v2::decode_state_v2;
use crate::types::Entry;
use crate::vault::{dispatch, ActiveSession, MemoryStore, SecretStore, StoreOp};

const PW: &str = "correct horse battery staple";
const PW2: &str = "another horse battery staple";

fn unlocked_v2(store: &mut MemoryStore) -> VaultSessionV2 {
    let mut session = VaultSessionV2::create_with_params(
        store,
        PW,
        Argon2ParamsV2::insecure_for_tests(),
    )
    .expect("v2 create");
    let mut e = Entry::new("e1", "Mail");
    e.password = "inbox-secret".into();
    session.doc.entries.insert(e.id.clone(), e);
    session.persist(store).expect("persist");
    session
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn random_blob(state: &mut u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for chunk in out.chunks_mut(8) {
        let n = xorshift(state).to_le_bytes();
        let n = &n[..chunk.len()];
        chunk.copy_from_slice(n);
    }
    out
}

fn assert_no_panic_parse(bytes: &[u8]) {
    let _ = MasterEnvelopeV2::from_bytes(bytes);
    let _ = VaultBlobV2::from_bytes(bytes);
    let _ = BackupEnvelopeV2::from_bytes(bytes);
    let _ = RecoveryWrapV2::from_kit_bytes(bytes);
    let _ = decode_state_v2(bytes);
    let _ = ShareEnvelopeV2::from_cbor(bytes);
    let _ = MasterEnvelope::from_cbor(bytes);
}

#[test]
fn parser_random_and_mutated_inputs_fail_closed() {
    let mut store = MemoryStore::default();
    let session = unlocked_v2(&mut store);
    let env = store.get(SECRET_ENVELOPE_V2).unwrap();
    let vault = store.get(SECRET_VAULT_V2).unwrap();
    let backup = session.export_backup(PW).unwrap();
    let rec = crate::recovery_v2::wrap_recovery(
        &crate::crypto::secret::RootSecret::from_bytes(session.root_bytes_for_test()),
        session.vault_id_for_test(),
        session.key_epoch_for_test(),
    )
    .unwrap()
    .0
    .to_kit_bytes()
    .unwrap();

    let fixtures = [env.as_slice(), vault.as_slice(), backup.as_slice(), rec.as_slice()];
    for f in fixtures {
        assert_no_panic_parse(f);
        let mut mutated = f.to_vec();
        if !mutated.is_empty() {
            mutated[0] ^= 0xff;
            assert_no_panic_parse(&mutated);
            let last = mutated.len() - 1;
            mutated[last] ^= 0x5a;
            assert_no_panic_parse(&mutated);
        }
    }

    let mut rng = 0xAE615_F022u64;
    for i in 0..256 {
        let len = (xorshift(&mut rng) as usize) % 2048;
        let blob = random_blob(&mut rng, len);
        assert_no_panic_parse(&blob);
        for magic in [
            MAGIC_VAULT_V2,
            MAGIC_BACKUP_V2,
            MAGIC_RECOVERY_V2,
            MAGIC_SYNC_V2,
        ] {
            let mut framed = magic.to_vec();
            framed.push(if i % 3 == 0 { 0x02 } else { 0x01 });
            framed.extend_from_slice(&blob);
            assert_no_panic_parse(&framed);
        }
    }

    assert_eq!(
        MasterEnvelopeV2::from_bytes(&vec![0u8; MAX_VAULT_FILE + 1]),
        Err(CryptoError::ResourceLimit)
    );
    assert_eq!(
        BackupEnvelopeV2::from_bytes(&vec![0u8; MAX_BACKUP_FILE + 1]),
        Err(CryptoError::ResourceLimit)
    );
    assert_eq!(
        RecoveryWrapV2::from_kit_bytes(&vec![0u8; crate::recovery_v2::MAX_RECOVERY_KIT_FILE + 1]),
        Err(CryptoError::ResourceLimit)
    );
}

#[test]
fn vault_blob_is_not_a_master_envelope_and_backup_is_not_a_kit() {
    let mut store = MemoryStore::default();
    let session = unlocked_v2(&mut store);
    let env = store.get(SECRET_ENVELOPE_V2).unwrap();
    let vault = store.get(SECRET_VAULT_V2).unwrap();
    assert!(MasterEnvelopeV2::from_bytes(&env).is_ok());
    assert!(VaultBlobV2::from_bytes(&vault).is_ok());
    assert!(MasterEnvelopeV2::from_bytes(&vault).is_err());
    assert!(VaultBlobV2::from_bytes(&env).is_err());

    let backup = session.export_backup(PW).unwrap();
    assert!(backup.starts_with(MAGIC_BACKUP_V2));
    assert!(RecoveryWrapV2::from_kit_bytes(&backup).is_err());
    assert!(BackupEnvelopeV2::from_bytes(&env).is_err());
    let kit = crate::recovery_v2::wrap_recovery(
        &crate::crypto::secret::RootSecret::from_bytes(session.root_bytes_for_test()),
        session.vault_id_for_test(),
        session.key_epoch_for_test(),
    )
    .unwrap()
    .0
    .to_kit_bytes()
    .unwrap();
    assert!(kit.starts_with(MAGIC_RECOVERY_V2));
    assert!(BackupEnvelopeV2::from_bytes(&kit).is_err());
    assert!(authenticate_backup(&kit, PW).is_err());
}

#[test]
fn truncated_nonce_and_unknown_fields_fail_closed() {
    let mut store = MemoryStore::default();
    let _ = unlocked_v2(&mut store);
    let env = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    let mut short = env.clone();
    short.wrap_nonce.truncate(8);
    assert!(MasterEnvelopeV2::from_cbor(&short.to_cbor().unwrap()).is_err());
}

#[test]
fn persist_and_passphrase_change_are_atomic() {
    struct FailCommitStore {
        inner: MemoryStore,
        fail: bool,
    }
    impl SecretStore for FailCommitStore {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.get(key)
        }
        fn set(&mut self, key: &[u8], value: &[u8]) {
            self.inner.set(key, value)
        }
        fn remove(&mut self, key: &[u8]) {
            self.inner.remove(key)
        }
        fn commit(&mut self, ops: &[StoreOp]) -> Result<(), String> {
            if self.fail {
                return Err("simulated persistence failure".into());
            }
            self.inner.commit(ops)
        }
    }

    let mut inner = MemoryStore::default();
    let mut session = unlocked_v2(&mut inner);
    let mut store = FailCommitStore {
        inner,
        fail: true,
    };
    let before = store.inner.durable_pairs();
    session.doc.entries.get_mut("e1").unwrap().password = "changed".into();
    assert!(session.persist(&mut store).is_err());
    assert_eq!(store.inner.durable_pairs(), before);

    store.fail = false;
    session.persist(&mut store).unwrap();
    store.fail = true;
    let before = store.inner.durable_pairs();
    assert!(session.change_passphrase(&mut store, PW, PW2).is_err());
    assert_eq!(store.inner.durable_pairs(), before);
}

#[test]
fn v1_parser_rejects_v2_magic_and_oversized() {
    let mut v2ish = MAGIC_VAULT_V2.to_vec();
    v2ish.push(0x02);
    v2ish.extend_from_slice(&[0xa0]);
    assert!(MasterEnvelope::from_cbor(&v2ish).is_err());
    assert_eq!(
        MasterEnvelope::from_cbor(&vec![0u8; 16 * 1024 * 1024 + 1]),
        Err(CryptoError::ResourceLimit)
    );
}

#[test]
fn dispatch_does_not_mutate_store_on_garbage_import() {
    let mut store = MemoryStore::default();
    let mut session = Some(ActiveSession::V2(unlocked_v2(&mut store)));
    let before = store.durable_pairs();
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::ImportEncrypted {
            blob: vec![0xff; 64],
            passphrase: PW.into(),
            new_passphrase: Some(PW2.into()),
            replace: true,
        },
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(store.durable_pairs(), before);
}
