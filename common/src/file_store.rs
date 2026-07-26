//! Disk-backed secret store for the local dev vault server.

use crate::vault::{SecretStore, SECRET_SESSION};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Persists secrets under `dir/` as hex-named files. Session key stays memory-only.
pub struct FileStore {
    dir: PathBuf,
    map: HashMap<Vec<u8>, Vec<u8>>,
}

impl FileStore {
    pub fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let mut map = HashMap::new();
        if let Ok(entries) = fs::read_dir(&dir) {
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
                        map.insert(key, val);
                    }
                }
            }
        }
        Ok(Self { dir, map })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, key: &[u8]) -> PathBuf {
        self.dir.join(format!("{}.bin", hex::encode(key)))
    }
}

impl SecretStore for FileStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.map.insert(key.to_vec(), value.to_vec());
        // Never persist unlocked session key material.
        if key == SECRET_SESSION {
            return;
        }
        let path = self.path_for(key);
        if let Err(e) = fs::write(&path, value) {
            eprintln!("aegis FileStore: failed to write {}: {e}", path.display());
        }
    }

    fn remove(&mut self, key: &[u8]) {
        self.map.remove(key);
        if key == SECRET_SESSION {
            return;
        }
        let path = self.path_for(key);
        let _ = fs::remove_file(path);
    }
}
