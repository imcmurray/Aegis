//! Copy a secret without embedding it in a shell argv, then timed wipe.

use crate::paths::CLIPBOARD_CLEAR_SECONDS;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn copy_secret(secret: &str, stdout: bool) -> Result<(), String> {
    if stdout {
        let mut out = std::io::stdout().lock();
        out.write_all(secret.as_bytes())
            .map_err(|e| e.to_string())?;
        out.write_all(b"\n").map_err(|e| e.to_string())?;
        return Ok(());
    }
    if let Ok(path) = std::env::var("AEGIS_CLIPBOARD_FILE") {
        write_file(&path, secret)?;
        return Ok(());
    }
    if let Ok(cmd) = std::env::var("AEGIS_CLIPBOARD_CMD") {
        pipe_to(&cmd, &[], secret)?;
        return Ok(());
    }
    if which("wl-copy") {
        pipe_to("wl-copy", &[], secret)?;
        return Ok(());
    }
    if which("xclip") {
        pipe_to("xclip", &["-selection", "clipboard"], secret)?;
        return Ok(());
    }
    Err("no clipboard helper (wl-copy/xclip); use --stdout or AEGIS_CLIPBOARD_FILE".into())
}

pub fn clear_clipboard() -> Result<(), String> {
    if let Ok(path) = std::env::var("AEGIS_CLIPBOARD_FILE") {
        write_file(&path, "")?;
        return Ok(());
    }
    if let Ok(cmd) = std::env::var("AEGIS_CLIPBOARD_CMD") {
        pipe_to(&cmd, &[], "")?;
        return Ok(());
    }
    if which("wl-copy") {
        let _ = Command::new("wl-copy").arg("--clear").status();
        let _ = pipe_to("wl-copy", &[], "");
        return Ok(());
    }
    if which("xclip") {
        pipe_to("xclip", &["-selection", "clipboard"], "")?;
        return Ok(());
    }
    Ok(())
}

pub fn spawn_wipe(seconds: u64) -> Result<(), String> {
    let secs = if seconds == 0 {
        CLIPBOARD_CLEAR_SECONDS
    } else {
        seconds
    };
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(exe);
    cmd.arg("__wipe-clipboard")
        .arg("--seconds")
        .arg(secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Ok(v) = std::env::var("AEGIS_CLIPBOARD_FILE") {
        cmd.env("AEGIS_CLIPBOARD_FILE", v);
    }
    if let Ok(v) = std::env::var("AEGIS_CLIPBOARD_CMD") {
        cmd.env("AEGIS_CLIPBOARD_CMD", v);
    }
    if let Ok(v) = std::env::var("AEGIS_CLIPBOARD_ARG") {
        cmd.env("AEGIS_CLIPBOARD_ARG", v);
    }
    cmd.spawn().map_err(|e| e.to_string())?;
    Ok(())
}

fn pipe_to(program: &str, args: &[&str], secret: &str) -> Result<(), String> {
    let mut extra: Vec<String> = Vec::new();
    if let Ok(a) = std::env::var("AEGIS_CLIPBOARD_ARG") {
        extra.push(a);
    }
    let mut child = Command::new(program);
    child.args(args).args(&extra).stdin(Stdio::piped());
    let mut child = child.spawn().map_err(|e| format!("{program}: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(secret.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let st = child.wait().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err(format!("{program} exited {st}"));
    }
    Ok(())
}

fn write_file(path: &str, secret: &str) -> Result<(), String> {
    let p = PathBuf::from(path);
    fs::write(&p, secret).map_err(|e| e.to_string())
}

fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p).any(|dir| {
                let cand = dir.join(name);
                cand.is_file()
            })
        })
        .unwrap_or(false)
}

pub fn wipe_after(seconds: u64) {
    std::thread::sleep(std::time::Duration::from_secs(seconds));
    let _ = clear_clipboard();
}

#[allow(dead_code)]
pub fn clipboard_file_path() -> Option<PathBuf> {
    std::env::var_os("AEGIS_CLIPBOARD_FILE").map(PathBuf::from)
}

#[allow(dead_code)]
pub fn is_file(path: &Path) -> bool {
    path.is_file()
}
