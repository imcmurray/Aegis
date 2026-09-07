//! Generation-based atomic commit for stores whose *single-key* `set` is atomic
//! but a sequential multi-key `commit` is not (Freenet secret store).
//!
//! Candidate keys are written under `aegis/gen/<id>/…` and stay invisible until
//! `aegis/v1/active-gen` is switched — that pointer write is the commit point.

use crate::rng;
use crate::vault::{apply_store_ops, SecretStore, StoreOp, SECRET_KEYS_V2, VAULT_INSTANCE_KEYS};

fn tracked_keys() -> impl Iterator<Item = &'static [u8]> {
    VAULT_INSTANCE_KEYS
        .iter()
        .copied()
        .chain(SECRET_KEYS_V2.iter().copied())
}

pub const ACTIVE_GEN_KEY: &[u8] = b"aegis/v1/active-gen";
const GEN_PREFIX: &[u8] = b"aegis/gen/";

/// Wraps a backend where each `set`/`remove` is independently durable.
pub struct GenerationStore<S> {
    inner: S,
}

impl<S: SecretStore> GenerationStore<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    fn current_gen(&self) -> Option<Vec<u8>> {
        self.inner.get(ACTIVE_GEN_KEY)
    }

    fn prefixed(gen: &[u8], key: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(GEN_PREFIX.len() + gen.len() + 1 + key.len());
        out.extend_from_slice(GEN_PREFIX);
        out.extend_from_slice(gen);
        out.push(b'/');
        out.extend_from_slice(key);
        out
    }

    fn new_gen_id() -> Vec<u8> {
        let mut raw = [0u8; 16];
        rng::fill_random(&mut raw);
        hex::encode(raw).into_bytes()
    }

    fn gc_gen(&mut self, gen: &[u8]) {
        for key in tracked_keys() {
            self.inner.remove(&Self::prefixed(gen, key));
        }
    }

    fn gc_legacy_unprefixed(&mut self) {
        for key in tracked_keys() {
            self.inner.remove(key);
        }
    }
}

impl<S: SecretStore> SecretStore for GenerationStore<S> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if key == ACTIVE_GEN_KEY {
            return self.inner.get(key);
        }
        if let Some(gen) = self.current_gen() {
            self.inner.get(&Self::prefixed(&gen, key))
        } else {
            self.inner.get(key)
        }
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        if key == ACTIVE_GEN_KEY {
            self.inner.set(key, value);
            return;
        }
        if let Some(gen) = self.current_gen() {
            self.inner.set(&Self::prefixed(&gen, key), value);
        } else {
            self.inner.set(key, value);
        }
    }

    fn remove(&mut self, key: &[u8]) {
        if key == ACTIVE_GEN_KEY {
            self.inner.remove(key);
            return;
        }
        if let Some(gen) = self.current_gen() {
            self.inner.remove(&Self::prefixed(&gen, key));
        } else {
            self.inner.remove(key);
        }
    }

    fn commit(&mut self, ops: &[StoreOp]) -> Result<(), String> {
        let old_gen = self.current_gen();
        let new_gen = Self::new_gen_id();

        let mut snap = std::collections::HashMap::new();
        for key in tracked_keys() {
            if let Some(v) = self.get(key) {
                snap.insert(key.to_vec(), v);
            }
        }
        for op in ops {
            let key = match op {
                StoreOp::Put { key, .. } | StoreOp::Delete { key } => key,
            };
            if key.as_slice() == ACTIVE_GEN_KEY {
                continue;
            }
            if !snap.contains_key(key) {
                if let Some(v) = self.get(key) {
                    snap.insert(key.clone(), v);
                }
            }
        }
        apply_store_ops(&mut snap, ops);

        for (key, value) in &snap {
            self.inner.set(&Self::prefixed(&new_gen, key), value);
        }
        for (key, value) in &snap {
            let got = self.inner.get(&Self::prefixed(&new_gen, key));
            if got.as_deref() != Some(value.as_slice()) {
                return Err("generation candidate failed verification".into());
            }
        }

        // Commit point: a single-key pointer switch.
        self.inner.set(ACTIVE_GEN_KEY, &new_gen);

        if let Some(old) = old_gen {
            self.gc_gen(&old);
        } else {
            self.gc_legacy_unprefixed();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{MemoryStore, SECRET_ENVELOPE, SECRET_RECOVERY, SECRET_VAULT};

    #[test]
    fn pointer_switch_is_the_commit_point() {
        let mut raw = MemoryStore::default();
        raw.set(SECRET_ENVELOPE, b"old-env");
        raw.set(SECRET_VAULT, b"old-vault");
        raw.set(SECRET_RECOVERY, b"old-recovery");

        let mut store = GenerationStore::new(raw);
        store
            .commit(&[
                StoreOp::put(SECRET_ENVELOPE, b"new-env".to_vec()),
                StoreOp::put(SECRET_VAULT, b"new-vault".to_vec()),
                StoreOp::delete(SECRET_RECOVERY),
            ])
            .unwrap();

        assert_eq!(store.get(SECRET_ENVELOPE).unwrap(), b"new-env");
        assert_eq!(store.get(SECRET_VAULT).unwrap(), b"new-vault");
        assert!(store.get(SECRET_RECOVERY).is_none());

        let inner = store.into_inner();
        assert!(inner.get(ACTIVE_GEN_KEY).is_some());
        assert!(
            inner.get(SECRET_RECOVERY).is_none(),
            "legacy unprefixed recovery must be GC'd after first generation commit"
        );
    }

    #[test]
    fn crash_before_pointer_keeps_old_vault() {
        let mut raw = MemoryStore::default();
        raw.set(SECRET_ENVELOPE, b"old-env");
        raw.set(SECRET_VAULT, b"old-vault");

        let new_gen = b"cafebabedeadbeef".to_vec();
        raw.set(
            &GenerationStore::<MemoryStore>::prefixed(&new_gen, SECRET_ENVELOPE),
            b"new-env",
        );
        raw.set(
            &GenerationStore::<MemoryStore>::prefixed(&new_gen, SECRET_VAULT),
            b"new-vault",
        );
        // No ACTIVE_GEN_KEY — pointer never switched.

        let store = GenerationStore::new(raw);
        assert_eq!(store.get(SECRET_ENVELOPE).unwrap(), b"old-env");
        assert_eq!(store.get(SECRET_VAULT).unwrap(), b"old-vault");
    }
}
