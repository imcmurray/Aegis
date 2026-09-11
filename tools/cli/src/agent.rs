//! Unix-socket session daemon. Holds FileStore + optional ActiveSession.

use crate::paths::{chmod_file, AegisPaths};
use crate::rpc::{read_frame, write_frame};
use aegis_common::file_store::FileStore;
use aegis_common::messages::VaultRequest;
use aegis_common::sync::FileSyncTransport;
use aegis_common::vault::ActiveSession;
use std::fs;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct AppState {
    pub store: FileStore,
    pub session: Option<ActiveSession>,
    pub sync: FileSyncTransport,
    pub last_activity: Instant,
    pub lock_after: Duration,
}

pub fn run_foreground(paths: &AegisPaths, lock_after_secs: u64) -> io::Result<()> {
    paths.ensure_data()?;
    paths.ensure_runtime()?;
    let sock = paths.socket_path();
    let pid = paths.pid_path();
    cleanup_stale(&sock, &pid)?;
    if sock.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("agent already running ({})", sock.display()),
        ));
    }
    let _ = fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    chmod_file(&sock, 0o600)?;
    fs::write(&pid, format!("{}\n", std::process::id()))?;
    chmod_file(&pid, 0o600)?;

    let store = FileStore::open(paths.secrets_dir())
        .map_err(|e| io::Error::other(format!("open store: {e}")))?;
    let sync = FileSyncTransport::open(paths.sync_path());
    let state = Arc::new(Mutex::new(AppState {
        store,
        session: None,
        sync,
        last_activity: Instant::now(),
        lock_after: Duration::from_secs(lock_after_secs.max(1)),
    }));

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        let state = state.clone();
        let _ = ctrlc::set_handler(move || {
            if let Ok(mut g) = state.lock() {
                let _ = crate::rpc::handle_state(&mut g, VaultRequest::Lock);
            }
            stop.store(true, Ordering::SeqCst);
        });
    }

    tracing::info!(
        data = %paths.data_dir.display(),
        sock = %sock.display(),
        "agent listening"
    );

    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        maybe_autolock(&state);
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(e) = serve_one(&state, stream) {
                    tracing::warn!(error = %e, "agent connection");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    let _ = fs::remove_file(&sock);
    let _ = fs::remove_file(&pid);
    Ok(())
}

fn maybe_autolock(state: &Mutex<AppState>) {
    let mut g = match state.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if g.session.is_some() && g.last_activity.elapsed() >= g.lock_after {
        let _ = crate::rpc::handle_state(&mut g, VaultRequest::Lock);
    }
}

fn serve_one(state: &Mutex<AppState>, mut stream: UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    let bytes = read_frame(&mut stream)?;
    let req = VaultRequest::from_cbor(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let resp = {
        let mut g = state
            .lock()
            .map_err(|_| io::Error::other("agent mutex poisoned"))?;
        if g.session.is_some() && g.last_activity.elapsed() >= g.lock_after {
            let _ = crate::rpc::handle_state(&mut g, VaultRequest::Lock);
        }
        let resp = crate::rpc::handle_state(&mut g, req);
        g.last_activity = Instant::now();
        resp
    };
    let out = resp
        .to_cbor()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(&mut stream, &out)
}

fn cleanup_stale(sock: &Path, pid: &Path) -> io::Result<()> {
    if !pid.exists() {
        if sock.exists() {
            let _ = fs::remove_file(sock);
        }
        return Ok(());
    }
    let raw = fs::read_to_string(pid)?;
    let n: i32 = raw.trim().parse().unwrap_or(0);
    if n > 0 && process_alive(n) {
        return Ok(());
    }
    let _ = fs::remove_file(pid);
    let _ = fs::remove_file(sock);
    Ok(())
}

pub fn process_alive(pid: i32) -> bool {
    // SAFETY: kill(pid, 0) is a existence check.
    unsafe { libc::kill(pid, 0) == 0 }
}

pub fn running_pid(paths: &AegisPaths) -> Option<i32> {
    let raw = fs::read_to_string(paths.pid_path()).ok()?;
    let n: i32 = raw.trim().parse().ok()?;
    if n > 0 && process_alive(n) && paths.socket_path().exists() {
        Some(n)
    } else {
        None
    }
}

pub fn stop(paths: &AegisPaths) -> io::Result<()> {
    match running_pid(paths) {
        Some(pid) => {
            // SAFETY: SIGTERM to our agent pid.
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            for _ in 0..50 {
                if !process_alive(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = fs::remove_file(paths.socket_path());
            let _ = fs::remove_file(paths.pid_path());
            Ok(())
        }
        None => {
            let _ = fs::remove_file(paths.socket_path());
            let _ = fs::remove_file(paths.pid_path());
            Ok(())
        }
    }
}

pub fn spawn_detached(paths: &AegisPaths, lock_after: u64) -> io::Result<()> {
    paths.ensure_runtime()?;
    if running_pid(paths).is_some() {
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("agent")
        .arg("--foreground")
        .arg("--data-dir")
        .arg(&paths.data_dir)
        .arg("--runtime-dir")
        .arg(&paths.runtime_dir)
        .arg("--lock-after")
        .arg(lock_after.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if crate::paths::test_kdf() {
        cmd.env("AEGIS_KDF", "test");
    }
    cmd.spawn()?;
    for _ in 0..100 {
        if running_pid(paths).is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "agent socket did not appear",
    ))
}


