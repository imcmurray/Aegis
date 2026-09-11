//! Integration tests for the native `aegis` CLI.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aegis"))
}

struct Harness {
    data: PathBuf,
    runtime: PathBuf,
    pwfile: PathBuf,
    clip: PathBuf,
    _tmp: tempfile_dir::Tmp,
}

mod tempfile_dir {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub struct Tmp(pub PathBuf);
    impl Tmp {
        pub fn new() -> Self {
            let n = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!("aegis-cli-test-{n}-{}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

impl Harness {
    fn new() -> Self {
        let tmp = tempfile_dir::Tmp::new();
        let data = tmp.0.join("data");
        let runtime = tmp.0.join("run");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        let pwfile = tmp.0.join("pw");
        write_secret_file(&pwfile, "correct horse battery staple");
        let clip = tmp.0.join("clip");
        Self {
            data,
            runtime,
            pwfile,
            clip,
            _tmp: tmp,
        }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(bin());
        c.env("AEGIS_KDF", "test")
            .env("AEGIS_CLIPBOARD_FILE", &self.clip)
            .arg("--data-dir")
            .arg(&self.data)
            .arg("--runtime-dir")
            .arg(&self.runtime);
        c
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let mut c = self.cmd();
        c.args(args);
        let out = c.output().expect("run aegis");
        (
            out.status.code().unwrap_or(1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn run_pw(&self, args: &[&str], pwfile: &Path) -> (i32, String, String) {
        let mut c = self.cmd();
        c.arg("--passphrase-file").arg(pwfile).args(args);
        let out = c.output().expect("run aegis");
        (
            out.status.code().unwrap_or(1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn rpc_line(&self, json: &str) -> (i32, String, String) {
        let mut c = self.cmd();
        c.arg("rpc").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(json.as_bytes())
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        (
            out.status.code().unwrap_or(1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn stop_agent(&self) {
        let _ = self.run(&["agent", "stop"]);
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop_agent();
    }
}

fn json_vault_id(stdout: &str) -> Option<String> {
    let key = "\"vault_id\":\"";
    let i = stdout.find(key)? + key.len();
    let rest = &stdout[i..];
    let end = rest.find('"')?;
    let id = &rest[..end];
    if id.is_empty() || id == "null" {
        None
    } else {
        Some(id.to_string())
    }
}

fn write_secret_file(path: &Path, s: &str) {
    fs::write(path, s).unwrap();
    let mut p = fs::metadata(path).unwrap().permissions();
    p.set_mode(0o600);
    fs::set_permissions(path, p).unwrap();
}

#[test]
fn help_has_no_example_secret() {
    let out = Command::new(bin()).arg("--help").output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("Aegis"));
    assert!(!s.to_lowercase().contains("correct horse"));
    assert!(!s.contains("--passphrase "));
}

#[test]
fn protocol_version_is_1() {
    let out = Command::new(bin())
        .arg("--protocol-version")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1");
}

#[test]
fn create_status_locked_without_agent() {
    let h = Harness::new();
    let (c, o, e) = h.run_pw(&["create"], &h.pwfile);
    assert_eq!(c, 0, "create failed: {e} {o}");
    let (c, o, e) = h.run(&["--json", "status"]);
    assert_eq!(c, 0, "status failed: {e} {o}");
    assert!(o.contains("\"has_vault\":true"), "{o}");
    assert!(o.contains("\"unlocked\":false"), "{o}");
}

#[test]
fn unlock_agent_search_copy_lock() {
    let h = Harness::new();
    let (c, o, e) = h.run_pw(&["create"], &h.pwfile);
    assert_eq!(c, 0, "create: {e} {o}");

    let (c, o, e) = h.run_pw(&["unlock"], &h.pwfile);
    assert_eq!(c, 0, "unlock: {e} {o}");
    let (c, o, e) = h.run(&["agent", "status"]);
    assert_eq!(c, 0, "{e} {o}");
    assert!(o.contains("pid="), "{o}");
    let pid1 = o.trim().to_string();

    let upsert = r#"{"op":"upsert_entry","entry":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","folder_id":null,"name":"Mail","urls":[],"username":"user-mail","password":"inbox-secret","notes":"","custom_fields":[],"tags":[],"created_at":1,"updated_at":1}}"#;
    let (c, o, e) = h.rpc_line(upsert);
    assert_eq!(c, 0, "upsert: {e} {o}");
    assert!(o.contains("\"type\":\"ok\"") || o.contains("\"type\":\"unlocked\""), "{o}");

    let (c, o, e) = h.run(&["search", "Mail"]);
    assert_eq!(c, 0, "search: {e} {o}");
    assert!(o.contains("Mail"), "{o}");
    assert!(!o.contains("inbox-secret"), "search leaked password: {o}");

    let (c, o, e) = h.run(&["copy", "Mail", "--no-clear"]);
    assert_eq!(c, 0, "copy: {e} {o}");
    let clip = fs::read_to_string(&h.clip).unwrap_or_default();
    assert_eq!(clip, "inbox-secret");

    let (c, o, e) = h.run(&["agent", "status"]);
    assert_eq!(c, 0, "{e} {o}");
    assert_eq!(o.trim(), pid1.trim(), "agent pid changed; KDF may have rerun");

    let (c, o, e) = h.run(&["lock"]);
    assert_eq!(c, 0, "lock: {e} {o}");
    let (c, o, e) = h.run(&["search", "Mail"]);
    assert_ne!(c, 0, "search after lock should fail: {o} {e}");
    assert!(
        e.contains("Locked") || o.contains("\"code\":\"locked\""),
        "expected Locked: stdout={o} stderr={e}"
    );
}

#[test]
fn export_import_new_identity() {
    let h = Harness::new();
    h.run_pw(&["create"], &h.pwfile);
    h.run_pw(&["unlock"], &h.pwfile);
    let upsert = r#"{"op":"upsert_entry","entry":{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","folder_id":null,"name":"Mail","urls":[],"username":"u","password":"secret-pw","notes":"","custom_fields":[],"tags":[],"created_at":1,"updated_at":1}}"#;
    h.rpc_line(upsert);

    let backup_pw = h._tmp.0.join("backup-pw");
    write_secret_file(&backup_pw, "backup horse battery");
    let aegis = h._tmp.0.join("vault.aegis");
    let (c, o, e) = h.run(&[
        "export",
        aegis.to_str().unwrap(),
        "--backup-passphrase-file",
        backup_pw.to_str().unwrap(),
    ]);
    assert_eq!(c, 0, "export: {e} {o}");
    assert!(aegis.is_file());

    let live2 = h._tmp.0.join("live2");
    write_secret_file(&live2, "another horse battery staple");
    let h2_data = h._tmp.0.join("data2");
    let h2_run = h._tmp.0.join("run2");
    fs::create_dir_all(&h2_data).unwrap();
    fs::create_dir_all(&h2_run).unwrap();
    let mut c = Command::new(bin());
    c.env("AEGIS_KDF", "test")
        .arg("--data-dir")
        .arg(&h2_data)
        .arg("--runtime-dir")
        .arg(&h2_run)
        .arg("import")
        .arg(&aegis)
        .arg("--backup-passphrase-file")
        .arg(&backup_pw)
        .arg("--new-passphrase-file")
        .arg(&live2);
    let out = c.output().unwrap();
    assert!(
        out.status.success(),
        "import: {} {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    let mut st = Command::new(bin());
    st.env("AEGIS_KDF", "test")
        .arg("--data-dir")
        .arg(&h2_data)
        .arg("--runtime-dir")
        .arg(&h2_run)
        .arg("--passphrase-file")
        .arg(&live2)
        .arg("unlock");
    assert!(st.output().unwrap().status.success());

    let mut se = Command::new(bin());
    se.env("AEGIS_KDF", "test")
        .arg("--data-dir")
        .arg(&h2_data)
        .arg("--runtime-dir")
        .arg(&h2_run)
        .arg("search")
        .arg("Mail");
    let out = se.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "search imported: {stdout} {}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("Mail"), "{stdout}");

    let mut stop = Command::new(bin());
    stop.arg("--data-dir")
        .arg(&h2_data)
        .arg("--runtime-dir")
        .arg(&h2_run)
        .arg("agent")
        .arg("stop");
    let _ = stop.output();
}

#[test]
fn import_without_replace_refuses_existing_vault() {
    let h = Harness::new();
    h.run_pw(&["create"], &h.pwfile);
    h.run_pw(&["unlock"], &h.pwfile);
    let upsert = r#"{"op":"upsert_entry","entry":{"id":"dddddddddddddddddddddddddddddddd","folder_id":null,"name":"Old","urls":[],"username":"u","password":"old-pw","notes":"","custom_fields":[],"tags":[],"created_at":1,"updated_at":1}}"#;
    h.rpc_line(upsert);
    let backup_pw = h._tmp.0.join("backup-pw");
    write_secret_file(&backup_pw, "backup horse battery");
    let aegis = h._tmp.0.join("vault.aegis");
    let (c, o, e) = h.run(&[
        "export",
        aegis.to_str().unwrap(),
        "--backup-passphrase-file",
        backup_pw.to_str().unwrap(),
    ]);
    assert_eq!(c, 0, "export: {e} {o}");

    let live2 = h._tmp.0.join("live2");
    write_secret_file(&live2, "another horse battery staple");
    let (c, o, e) = h.run(&[
        "--json",
        "import",
        aegis.to_str().unwrap(),
        "--backup-passphrase-file",
        backup_pw.to_str().unwrap(),
        "--new-passphrase-file",
        live2.to_str().unwrap(),
    ]);
    assert_ne!(c, 0, "import without --replace should fail: {o} {e}");
    assert!(
        e.to_lowercase().contains("already exists")
            || o.contains("already exists")
            || o.contains("\"code\""),
        "expected already-exists: stdout={o} stderr={e}"
    );
}

#[test]
fn import_replace_overwrites_and_search_finds_entry() {
    let src = Harness::new();
    src.run_pw(&["create"], &src.pwfile);
    src.run_pw(&["unlock"], &src.pwfile);
    let upsert = r#"{"op":"upsert_entry","entry":{"id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","folder_id":null,"name":"ImportedMail","urls":["https://mail.example"],"username":"ada","password":"inbox-secret","notes":"hi","custom_fields":[],"tags":[],"created_at":1,"updated_at":1}}"#;
    src.rpc_line(upsert);
    let backup_pw = src._tmp.0.join("backup-pw");
    write_secret_file(&backup_pw, "backup horse battery");
    let aegis = src._tmp.0.join("vault.aegis");
    let (c, o, e) = src.run(&[
        "export",
        aegis.to_str().unwrap(),
        "--backup-passphrase-file",
        backup_pw.to_str().unwrap(),
    ]);
    assert_eq!(c, 0, "export: {e} {o}");

    let dest = Harness::new();
    dest.run_pw(&["create"], &dest.pwfile);
    dest.run_pw(&["unlock"], &dest.pwfile);
    let (c, o, e) = dest.run(&["--json", "status"]);
    assert_eq!(c, 0, "dest status: {e} {o}");
    let dest_id_before = json_vault_id(&o).expect("dest vault_id");
    dest.rpc_line(r#"{"op":"upsert_entry","entry":{"id":"ffffffffffffffffffffffffffffffff","folder_id":null,"name":"Old","urls":[],"username":"u","password":"old-pw","notes":"","custom_fields":[],"tags":[],"created_at":1,"updated_at":1}}"#);
    dest.run(&["lock"]);
    dest.stop_agent();
    let live2 = dest._tmp.0.join("live2");
    write_secret_file(&live2, "another horse battery staple");
    let (c, o, e) = dest.run(&[
        "--json",
        "import",
        "--replace",
        "--backup-passphrase-file",
        backup_pw.to_str().unwrap(),
        "--new-passphrase-file",
        live2.to_str().unwrap(),
        aegis.to_str().unwrap(),
    ]);
    assert_eq!(c, 0, "import --replace: {e} {o}");

    let (c, o, e) = dest.run_pw(&["unlock"], &live2);
    assert_eq!(c, 0, "unlock imported: {e} {o}");
    let (c, o, e) = dest.run(&["--json", "status"]);
    assert_eq!(c, 0, "status after replace: {e} {o}");
    let dest_id_after = json_vault_id(&o).expect("dest vault_id after replace");
    assert_ne!(
        dest_id_before, dest_id_after,
        "ordinary --replace restore must mint a new vault_id"
    );
    let (c, o, e) = dest.run(&["search", "ImportedMail"]);
    assert_eq!(c, 0, "search: {e} {o}");
    assert!(o.contains("ImportedMail"), "{o}");
    assert!(!o.contains("inbox-secret"), "search leaked password: {o}");
    let (c, o, e) = dest.run(&["search", "Old"]);
    assert_eq!(c, 0, "{e} {o}");
    assert!(!o.contains("Old\t"), "old vault entry survived replace: {o}");
}

#[test]
fn import_preview_conflicts_with_replace() {
    let h = Harness::new();
    let dummy = h._tmp.0.join("x.aegis");
    fs::write(&dummy, b"not-a-vault").unwrap();
    let (c, o, e) = h.run(&[
        "import",
        "--preview",
        "--replace",
        dummy.to_str().unwrap(),
    ]);
    assert_ne!(c, 0, "preview+replace should fail: {o} {e}");
    assert!(
        e.contains("cannot be used with") || e.contains("conflict") || o.contains("cannot be used with"),
        "expected clap conflict: stdout={o} stderr={e}"
    );
}

#[test]
fn rpc_json_status_list_lock() {
    let h = Harness::new();
    h.run_pw(&["create"], &h.pwfile);
    h.run_pw(&["unlock"], &h.pwfile);
    let (c, o, e) = h.rpc_line(r#"{"op":"status"}"#);
    assert_eq!(c, 0, "{e} {o}");
    assert!(o.contains("\"type\":\"status\""), "{o}");
    assert!(o.contains("\"unlocked\":true"), "{o}");

    let upsert = r#"{"op":"upsert_entry","entry":{"id":"cccccccccccccccccccccccccccccccc","folder_id":null,"name":"X","urls":[],"username":"","password":"p","notes":"","custom_fields":[],"tags":[],"created_at":1,"updated_at":1}}"#;
    h.rpc_line(upsert);
    let (c, o, e) = h.rpc_line(r#"{"op":"list_summaries"}"#);
    assert_eq!(c, 0, "{e} {o}");
    assert!(o.contains("\"type\":\"summaries\""), "{o}");
    assert!(!o.contains("\"password\":\"p\""), "summaries leaked password");

    let (c, o, e) = h.rpc_line(r#"{"op":"lock"}"#);
    assert_eq!(c, 0, "{e} {o}");
    assert!(o.contains("\"type\":\"locked\"") || o.contains("\"type\":\"ok\""), "{o}");
}

#[test]
fn autolock_and_socket_mode() {
    let h = Harness::new();
    h.run_pw(&["create"], &h.pwfile);
    let mut child = h
        .cmd()
        .args(["agent", "--foreground", "--lock-after", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if h.runtime.join("agent.sock").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let sock = h.runtime.join("agent.sock");
    let meta = fs::metadata(&sock).expect("socket");
    assert_eq!(meta.permissions().mode() & 0o077, 0, "socket must be user-only");

    let (c, o, e) = h.run_pw(&["unlock"], &h.pwfile);
    assert_eq!(c, 0, "unlock: {e} {o}");
    std::thread::sleep(Duration::from_millis(1500));
    let (c, o, e) = h.run(&["search"]);
    assert_ne!(c, 0, "should be auto-locked: {o} {e}");
    let _ = child.kill();
    h.stop_agent();
}
