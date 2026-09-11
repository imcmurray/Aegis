//! XDG data/runtime paths. Never defaults to `aegis-dev`.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const DEFAULT_LOCK_AFTER_SECS: u64 = 300;
pub const CLIPBOARD_CLEAR_SECONDS: u64 = 30;
pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_RPC_FRAME: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AegisPaths {
    pub data_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl AegisPaths {
    pub fn resolve(data_dir: Option<PathBuf>, runtime_dir: Option<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.unwrap_or_else(default_data_dir),
            runtime_dir: runtime_dir.unwrap_or_else(default_runtime_dir),
        }
    }

    pub fn secrets_dir(&self) -> PathBuf {
        self.data_dir.join("secrets")
    }

    pub fn sync_path(&self) -> PathBuf {
        self.data_dir.join("sync").join("vault_sync.cbor")
    }

    pub fn socket_path(&self) -> PathBuf {
        self.runtime_dir.join("agent.sock")
    }

    pub fn pid_path(&self) -> PathBuf {
        self.runtime_dir.join("agent.pid")
    }

    pub fn ensure_data(&self) -> io::Result<()> {
        fs::create_dir_all(self.secrets_dir())?;
        fs::create_dir_all(self.data_dir.join("sync"))?;
        chmod_dir(&self.data_dir, 0o700)?;
        Ok(())
    }

    pub fn ensure_runtime(&self) -> io::Result<()> {
        fs::create_dir_all(&self.runtime_dir)?;
        chmod_dir(&self.runtime_dir, 0o700)?;
        Ok(())
    }
}

fn default_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("AEGIS_DATA") {
        return PathBuf::from(p);
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("aegis");
    }
    home_dir().join(".local/share/aegis")
}

fn default_runtime_dir() -> PathBuf {
    if let Ok(p) = std::env::var("AEGIS_RUNTIME") {
        return PathBuf::from(p);
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(xdg).join("aegis");
    }
    if let Ok(uid) = std::env::var("UID") {
        return PathBuf::from(format!("/run/user/{uid}/aegis"));
    }
    PathBuf::from(format!("/run/user/{}/aegis", unix_uid()))
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn unix_uid() -> u32 {
    #[cfg(unix)]
    {
        libc_uid()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(unix)]
fn libc_uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

fn chmod_dir(path: &Path, mode: u32) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)
}

pub fn chmod_file(path: &Path, mode: u32) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)
}

pub fn test_kdf() -> bool {
    matches!(
        std::env::var("AEGIS_KDF").ok().as_deref(),
        Some("test") | Some("TEST")
    )
}
