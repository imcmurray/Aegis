//! Disk-backed secret store for the local dev vault server.

use crate::vault::{apply_store_ops, SecretStore, StoreOp, SECRET_SESSION};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const COMMIT_MARKER: &str = "_aegis_commit";

#[derive(Serialize, Deserialize, Default)]
struct CommitPlan {
    puts: Vec<String>,
    deletes: Vec<String>,
}

/// Persists secrets under `dir/` as hex-named files. Session key stays memory-only.
pub struct FileStore {
    dir: PathBuf,
    map: HashMap<Vec<u8>, Vec<u8>>,
}

impl FileStore {
    pub fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let mut store = Self {
            dir,
            map: HashMap::new(),
        };
        store.recover_commit()?;
        if let Ok(entries) = fs::read_dir(&store.dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                    continue;
                }
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default();
                if let Ok(key) = hex::decode(name) {
                    if let Ok(val) = fs::read(&path) {
                        store.map.insert(key, val);
                    }
                }
            }
        }
        Ok(store)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, key: &[u8]) -> PathBuf {
        self.dir.join(format!("{}.bin", hex::encode(key)))
    }

    fn tmp_path_for(&self, key: &[u8]) -> PathBuf {
        self.path_for(key).with_extension("bin.tmp")
    }

    fn marker_path(&self) -> PathBuf {
        self.dir.join(COMMIT_MARKER)
    }

    fn fsync_dir(dir: &Path) -> std::io::Result<()> {
        File::open(dir)?.sync_all()
    }

    fn write_fsynced(path: &Path, data: &[u8]) -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    }

    fn recover_commit(&self) -> std::io::Result<()> {
        let marker = self.marker_path();
        if !marker.exists() {
            return Ok(());
        }
        let mut buf = Vec::new();
        File::open(&marker)?.read_to_end(&mut buf)?;
        let plan: CommitPlan = ciborium::from_reader(buf.as_slice()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("corrupt commit marker: {e}"),
            )
        })?;
        self.apply_plan(&plan)?;
        let _ = fs::remove_file(&marker);
        let _ = Self::fsync_dir(&self.dir);
        Ok(())
    }

    fn apply_plan(&self, plan: &CommitPlan) -> std::io::Result<()> {
        for hex_key in &plan.puts {
            let tmp = self.dir.join(format!("{hex_key}.bin.tmp"));
            let dest = self.dir.join(format!("{hex_key}.bin"));
            if tmp.exists() {
                fs::rename(&tmp, &dest)?;
            }
        }
        for hex_key in &plan.deletes {
            let dest = self.dir.join(format!("{hex_key}.bin"));
            let _ = fs::remove_file(dest);
        }
        Ok(())
    }
}

impl SecretStore for FileStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        let _ = self.commit(&[StoreOp::put(key, value.to_vec())]);
    }

    fn remove(&mut self, key: &[u8]) {
        let _ = self.commit(&[StoreOp::delete(key.to_vec())]);
    }

    fn commit(&mut self, ops: &[StoreOp]) -> Result<(), String> {
        let mut plan = CommitPlan::default();
        for op in ops {
            match op {
                StoreOp::Put { key, .. } | StoreOp::Delete { key } if key.as_slice() == SECRET_SESSION => {}
                StoreOp::Put { key, value } => {
                    let hex_key = hex::encode(key);
                    Self::write_fsynced(&self.tmp_path_for(key), value).map_err(|e| e.to_string())?;
                    plan.puts.push(hex_key);
                }
                StoreOp::Delete { key } => {
                    plan.deletes.push(hex::encode(key));
                }
            }
        }

        if plan.puts.is_empty() && plan.deletes.is_empty() {
            apply_store_ops(&mut self.map, ops);
            return Ok(());
        }

        let mut marker_bytes = Vec::new();
        ciborium::into_writer(&plan, &mut marker_bytes).map_err(|e| e.to_string())?;
        let marker_tmp = self.dir.join(format!("{COMMIT_MARKER}.tmp"));
        Self::write_fsynced(&marker_tmp, &marker_bytes).map_err(|e| e.to_string())?;
        fs::rename(&marker_tmp, self.marker_path()).map_err(|e| e.to_string())?;
        // Marker is the commit-to-recover point: flush dir metadata before any data rename.
        Self::fsync_dir(&self.dir).map_err(|e| e.to_string())?;

        self.apply_plan(&plan).map_err(|e| e.to_string())?;
        Self::fsync_dir(&self.dir).map_err(|e| e.to_string())?;
        let _ = fs::remove_file(self.marker_path());
        let _ = Self::fsync_dir(&self.dir);

        apply_store_ops(&mut self.map, ops);
        // Session already applied above; apply_store_ops is idempotent for those.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{SECRET_ENVELOPE, SECRET_VAULT};

    fn tmpdir() -> PathBuf {
        let mut nonce = [0u8; 8];
        crate::rng::fill_random(&mut nonce);
        let dir = std::env::temp_dir().join(format!(
            "aegis-filestore-{}-{}",
            std::process::id(),
            hex::encode(nonce)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn commit_is_all_or_nothing_in_memory() {
        let dir = tmpdir();
        let mut store = FileStore::open(&dir).unwrap();
        store
            .commit(&[StoreOp::put(SECRET_ENVELOPE, b"old-env".to_vec())])
            .unwrap();

        store
            .commit(&[
                StoreOp::put(SECRET_ENVELOPE, b"new-env".to_vec()),
                StoreOp::put(SECRET_VAULT, b"new-vault".to_vec()),
            ])
            .unwrap();
        assert_eq!(store.get(SECRET_ENVELOPE).unwrap(), b"new-env");
        assert_eq!(store.get(SECRET_VAULT).unwrap(), b"new-vault");

        let reopened = FileStore::open(&dir).unwrap();
        assert_eq!(reopened.get(SECRET_ENVELOPE).unwrap(), b"new-env");
        assert_eq!(reopened.get(SECRET_VAULT).unwrap(), b"new-vault");
        let _ = fs::remove_dir_all(&dir);
    }

    fn hex_key(key: &[u8]) -> String {
        hex::encode(key)
    }

    fn write_bin(dir: &Path, key: &[u8], val: &[u8]) {
        fs::write(dir.join(format!("{}.bin", hex_key(key))), val).unwrap();
    }

    fn write_tmp(dir: &Path, key: &[u8], val: &[u8]) {
        fs::write(dir.join(format!("{}.bin.tmp", hex_key(key))), val).unwrap();
    }

    fn write_marker(dir: &Path, puts: &[&[u8]], deletes: &[&[u8]]) {
        let plan = CommitPlan {
            puts: puts.iter().map(|k| hex_key(k)).collect(),
            deletes: deletes.iter().map(|k| hex_key(k)).collect(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&plan, &mut bytes).unwrap();
        fs::write(dir.join(COMMIT_MARKER), bytes).unwrap();
    }

    #[test]
    fn crash_before_marker_keeps_old_files() {
        let dir = tmpdir();
        write_bin(&dir, SECRET_ENVELOPE, b"old-env");
        write_bin(&dir, SECRET_VAULT, b"old-vault");
        write_tmp(&dir, SECRET_ENVELOPE, b"new-env");
        write_tmp(&dir, SECRET_VAULT, b"new-vault");
        let store = FileStore::open(&dir).unwrap();
        assert_eq!(store.get(SECRET_ENVELOPE).unwrap(), b"old-env");
        assert_eq!(store.get(SECRET_VAULT).unwrap(), b"old-vault");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_after_marker_before_rename_recovers_new() {
        let dir = tmpdir();
        write_bin(&dir, SECRET_ENVELOPE, b"old-env");
        write_bin(&dir, SECRET_VAULT, b"old-vault");
        write_tmp(&dir, SECRET_ENVELOPE, b"new-env");
        write_tmp(&dir, SECRET_VAULT, b"new-vault");
        write_marker(&dir, &[SECRET_ENVELOPE, SECRET_VAULT], &[]);
        let store = FileStore::open(&dir).unwrap();
        assert_eq!(store.get(SECRET_ENVELOPE).unwrap(), b"new-env");
        assert_eq!(store.get(SECRET_VAULT).unwrap(), b"new-vault");
        assert!(!store.marker_path().exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_after_first_rename_recovers_new() {
        let dir = tmpdir();
        write_bin(&dir, SECRET_ENVELOPE, b"new-env"); // already renamed
        write_bin(&dir, SECRET_VAULT, b"old-vault");
        write_tmp(&dir, SECRET_VAULT, b"new-vault"); // pending
        write_marker(&dir, &[SECRET_ENVELOPE, SECRET_VAULT], &[]);
        let store = FileStore::open(&dir).unwrap();
        assert_eq!(store.get(SECRET_ENVELOPE).unwrap(), b"new-env");
        assert_eq!(store.get(SECRET_VAULT).unwrap(), b"new-vault");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_after_all_renames_before_marker_cleanup() {
        let dir = tmpdir();
        write_bin(&dir, SECRET_ENVELOPE, b"new-env");
        write_bin(&dir, SECRET_VAULT, b"new-vault");
        write_bin(&dir, crate::vault::SECRET_RECOVERY, b"old-recovery");
        write_marker(
            &dir,
            &[SECRET_ENVELOPE, SECRET_VAULT],
            &[crate::vault::SECRET_RECOVERY],
        );
        let store = FileStore::open(&dir).unwrap();
        assert_eq!(store.get(SECRET_ENVELOPE).unwrap(), b"new-env");
        assert_eq!(store.get(SECRET_VAULT).unwrap(), b"new-vault");
        assert!(store.get(crate::vault::SECRET_RECOVERY).is_none());
        assert!(!store.marker_path().exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_key_is_not_written_to_disk() {
        let dir = tmpdir();
        let mut store = FileStore::open(&dir).unwrap();
        store
            .commit(&[StoreOp::put(SECRET_SESSION, b"session-secret".to_vec())])
            .unwrap();
        assert!(store.get(SECRET_SESSION).is_some());
        let on_disk = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.path().extension().and_then(|s| s.to_str()) == Some("bin"));
        assert!(!on_disk, "session must not create a .bin file");
        let _ = fs::remove_dir_all(&dir);
    }
}
