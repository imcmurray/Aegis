//! Native Aegis CLI — production file-backed vault backend.

mod agent;
mod args;
mod clipboard;
mod paths;
mod rpc;

use aegis_common::crypto::GeneratorPolicy;
use aegis_common::file_store::FileStore;
use aegis_common::messages::{VaultRequest, VaultResponse};
use aegis_common::sync::FileSyncTransport;
use aegis_common::vault::ActiveSession;
use args::{AgentAction, Cli, Command, CopyField};
use clap::Parser;
use paths::{AegisPaths, PROTOCOL_VERSION};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_cli=info".into()),
        )
        .init();

    let cli = Cli::parse();
    if cli.protocol_version {
        println!("{PROTOCOL_VERSION}");
        return ExitCode::SUCCESS;
    }
    let Some(command) = cli.command else {
        eprintln!("error: missing command (try `aegis --help`)");
        return ExitCode::from(2);
    };
    match run(cli.data_dir, cli.runtime_dir, cli.json, cli.passphrase_file, command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(
    data_dir: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
    json: bool,
    passphrase_file: Option<PathBuf>,
    command: Command,
) -> Result<(), String> {
    let paths = AegisPaths::resolve(data_dir, runtime_dir);
    match command {
        Command::WipeClipboard { seconds } => {
            clipboard::wipe_after(seconds);
            Ok(())
        }
        Command::Agent(a) => match a.action {
            Some(AgentAction::Status) => {
                match agent::running_pid(&paths) {
                    Some(pid) => {
                        if json {
                            println!(
                                "{{\"type\":\"ok\",\"pid\":{pid},\"socket\":{}}}",
                                serde_json::to_string(&paths.socket_path())
                                    .unwrap_or_else(|_| "\"\"".into())
                            );
                        } else {
                            println!("agent running pid={pid}");
                        }
                    }
                    None => {
                        if json {
                            println!("{{\"type\":\"ok\",\"running\":false}}");
                        } else {
                            println!("agent not running");
                        }
                    }
                }
                Ok(())
            }
            Some(AgentAction::Stop) => {
                agent::stop(&paths).map_err(|e| e.to_string())?;
                if !json {
                    println!("agent stopped");
                } else {
                    println!("{{\"type\":\"ok\"}}");
                }
                Ok(())
            }
            None if a.foreground => {
                agent::run_foreground(&paths, a.lock_after).map_err(|e| e.to_string())
            }
            None => {
                agent::spawn_detached(&paths, a.lock_after).map_err(|e| e.to_string())?;
                if !json {
                    println!("agent started");
                } else {
                    println!("{{\"type\":\"ok\"}}");
                }
                Ok(())
            }
        },
        Command::Status => emit(json, dispatch_auto(&paths, VaultRequest::Status)?),
        Command::Create => {
            let pw = read_passphrase(passphrase_file.as_deref(), "New vault passphrase")?;
            if passphrase_file.is_none() && std::io::stdin().is_terminal() {
                let pw2 = read_passphrase(None, "Confirm passphrase")?;
                if *pw != *pw2 {
                    return Err("passphrases do not match".into());
                }
            }
            emit(
                json,
                dispatch_auto(
                    &paths,
                    VaultRequest::CreateVault {
                        passphrase: pw.to_string(),
                        kdf_profile: Default::default(),
                    },
                )?,
            )
        }
        Command::Unlock => {
            let pw = read_passphrase(passphrase_file.as_deref(), "Passphrase")?;
            if agent::running_pid(&paths).is_none() {
                agent::spawn_detached(&paths, paths::DEFAULT_LOCK_AFTER_SECS)
                    .map_err(|e| e.to_string())?;
            }
            emit(
                json,
                dispatch_auto(&paths, VaultRequest::Unlock { passphrase: pw.to_string() })?,
            )
        }
        Command::Lock => emit(json, dispatch_auto(&paths, VaultRequest::Lock)?),
        Command::Search { query } => emit(
            json,
            dispatch_auto(&paths, VaultRequest::ListSummaries { query })?,
        ),
        Command::Folders => emit(json, dispatch_auto(&paths, VaultRequest::ListFolders)?),
        Command::Generate => emit(
            json,
            dispatch_auto(
                &paths,
                VaultRequest::GeneratePassword {
                    policy: GeneratorPolicy::default(),
                },
            )?,
        ),
        Command::Copy {
            id_or_query,
            field,
            stdout,
            no_clear,
        } => copy_cmd(&paths, json, &id_or_query, field, stdout, no_clear),
        Command::Totp { id_or_query } => totp_cmd(&paths, json, &id_or_query),
        Command::Get { id, reveal } => get_cmd(&paths, json, &id, reveal),
        Command::Export {
            path,
            backup_passphrase_file,
        } => {
            let bpw = read_passphrase(
                backup_passphrase_file.as_deref().or(passphrase_file.as_deref()),
                "Backup passphrase",
            )?;
            let resp = dispatch_auto(
                &paths,
                VaultRequest::ExportEncrypted {
                    passphrase: bpw.to_string(),
                },
            )?;
            match &resp {
                VaultResponse::Export { blob } => {
                    fs::write(&path, blob).map_err(|e| e.to_string())?;
                    if json {
                        println!("{{\"type\":\"ok\",\"path\":{}}}", json_str(&path));
                    } else {
                        println!("wrote {}", path.display());
                    }
                    Ok(())
                }
                _ => emit(json, resp),
            }
        }
        Command::Import {
            path,
            preview,
            backup_passphrase_file,
            new_passphrase_file,
        } => {
            let blob = fs::read(&path).map_err(|e| e.to_string())?;
            let bpw = read_passphrase(
                backup_passphrase_file.as_deref().or(passphrase_file.as_deref()),
                "Backup passphrase",
            )?;
            if preview {
                return emit(
                    json,
                    dispatch_auto(
                        &paths,
                        VaultRequest::PreviewImport {
                            blob,
                            passphrase: bpw.to_string(),
                            local_passphrase: None,
                        },
                    )?,
                );
            }
            let npw = read_passphrase(
                new_passphrase_file.as_deref(),
                "New live vault passphrase",
            )?;
            if *npw == *bpw {
                return Err("new live-vault passphrase must differ from the backup passphrase".into());
            }
            emit(
                json,
                dispatch_auto(
                    &paths,
                    VaultRequest::ImportEncrypted {
                        blob,
                        passphrase: bpw.to_string(),
                        new_passphrase: Some(npw.to_string()),
                        replace: false,
                    },
                )?,
            )
        }
        Command::Rpc { cbor } => rpc_stdio(&paths, cbor),
    }
}

fn dispatch_auto(paths: &AegisPaths, req: VaultRequest) -> Result<VaultResponse, String> {
    if let Some(_pid) = agent::running_pid(paths) {
        return rpc::call_agent(&paths.socket_path(), &req).map_err(|e| e.to_string());
    }
    oneshot(paths, req)
}

fn oneshot(paths: &AegisPaths, req: VaultRequest) -> Result<VaultResponse, String> {
    paths.ensure_data().map_err(|e| e.to_string())?;
    let mut store = FileStore::open(paths.secrets_dir()).map_err(|e| e.to_string())?;
    let mut session: Option<ActiveSession> = None;
    let mut sync = FileSyncTransport::open(paths.sync_path());
    Ok(rpc::handle(&mut store, &mut session, &mut sync, req))
}

fn emit(json: bool, resp: VaultResponse) -> Result<(), String> {
    if let VaultResponse::Error { code, message } = &resp {
        if json {
            println!("{}", rpc::response_to_json(&resp)?);
        }
        return Err(format!("{code:?}: {message}"));
    }
    if json {
        println!("{}", rpc::response_to_json(&resp)?);
        return Ok(());
    }
    print_text(&resp);
    Ok(())
}

fn print_text(resp: &VaultResponse) {
    match resp {
        VaultResponse::Ok => println!("ok"),
        VaultResponse::Status {
            has_vault,
            unlocked,
            vault_id,
            vault_format,
            ..
        } => {
            println!(
                "has_vault={has_vault} unlocked={unlocked} format={} vault_id={}",
                vault_format.as_deref().unwrap_or("-"),
                vault_id.as_deref().unwrap_or("-")
            );
        }
        VaultResponse::Unlocked { vault_id } => println!("unlocked {vault_id}"),
        VaultResponse::Locked => println!("locked"),
        VaultResponse::Summaries { entries } => {
            for e in entries {
                println!(
                    "{}\t{}\t{}\t{}",
                    e.id,
                    e.name,
                    e.username,
                    if e.has_totp { "totp" } else { "" }
                );
            }
        }
        VaultResponse::Folders { folders } => {
            for f in folders {
                println!("{}\t{}", f.id, f.name);
            }
        }
        VaultResponse::Password { password } => println!("{password}"),
        VaultResponse::Totp {
            code,
            seconds_remaining,
            period,
        } => println!("{code} ({seconds_remaining}s / {period}s)"),
        VaultResponse::Entry { entry } => {
            println!("{}\t{}\t{}", entry.id, entry.name, entry.username);
        }
        VaultResponse::Export { blob } => println!("export {} bytes", blob.len()),
        VaultResponse::ImportPreview {
            backup_entry_count,
            same_vault_id,
            ..
        } => println!("preview backup_entries={backup_entry_count} same_id={same_vault_id}"),
        VaultResponse::Error { code, message } => eprintln!("{code:?}: {message}"),
        other => {
            if let Ok(s) = rpc::response_to_json(other) {
                println!("{s}");
            }
        }
    }
}

fn resolve_id(paths: &AegisPaths, id_or_query: &str) -> Result<String, String> {
    if looks_like_id(id_or_query) {
        let got = dispatch_auto(
            paths,
            VaultRequest::GetEntry {
                id: id_or_query.to_string(),
            },
        )?;
        if matches!(got, VaultResponse::Entry { .. }) {
            return Ok(id_or_query.to_string());
        }
    }
    let resp = dispatch_auto(
        paths,
        VaultRequest::ListSummaries {
            query: Some(id_or_query.to_string()),
        },
    )?;
    match resp {
        VaultResponse::Summaries { entries } if entries.len() == 1 => Ok(entries[0].id.clone()),
        VaultResponse::Summaries { entries } if entries.is_empty() => {
            Err("no matching entry".into())
        }
        VaultResponse::Summaries { entries } => Err(format!(
            "ambiguous query ({} matches); use an id",
            entries.len()
        )),
        VaultResponse::Error { code, message } => Err(format!("{code:?}: {message}")),
        _ => Err("unexpected search response".into()),
    }
}

fn looks_like_id(s: &str) -> bool {
    s.len() >= 8 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn copy_cmd(
    paths: &AegisPaths,
    json: bool,
    id_or_query: &str,
    field: CopyField,
    stdout: bool,
    no_clear: bool,
) -> Result<(), String> {
    let id = resolve_id(paths, id_or_query)?;
    let resp = dispatch_auto(paths, VaultRequest::GetEntry { id })?;
    let VaultResponse::Entry { entry } = resp else {
        return emit(json, resp);
    };
    let secret = match field {
        CopyField::Password => entry.password.clone(),
        CopyField::Username => entry.username.clone(),
        CopyField::Url => entry.urls.first().cloned().unwrap_or_default(),
        CopyField::Totp => {
            let secret = entry
                .totp_secret
                .clone()
                .ok_or_else(|| "entry has no totp secret".to_string())?;
            match dispatch_auto(
                paths,
                VaultRequest::GenerateTotp {
                    secret,
                    period: None,
                    digits: None,
                },
            )? {
                VaultResponse::Totp { code, .. } => code,
                other => return emit(json, other),
            }
        }
    };
    clipboard::copy_secret(&secret, stdout)?;
    if !stdout && !no_clear {
        clipboard::spawn_wipe(paths::CLIPBOARD_CLEAR_SECONDS)?;
    }
    if json {
        println!("{{\"type\":\"ok\",\"field\":\"{field:?}\"}}");
    } else if !stdout {
        println!("copied");
    }
    Ok(())
}

fn totp_cmd(paths: &AegisPaths, json: bool, id_or_query: &str) -> Result<(), String> {
    let id = resolve_id(paths, id_or_query)?;
    let resp = dispatch_auto(paths, VaultRequest::GetEntry { id })?;
    let VaultResponse::Entry { entry } = resp else {
        return emit(json, resp);
    };
    let secret = entry
        .totp_secret
        .ok_or_else(|| "entry has no totp secret".to_string())?;
    emit(
        json,
        dispatch_auto(
            paths,
            VaultRequest::GenerateTotp {
                secret,
                period: None,
                digits: None,
            },
        )?,
    )
}

fn get_cmd(paths: &AegisPaths, json: bool, id: &str, reveal: bool) -> Result<(), String> {
    let resp = dispatch_auto(
        paths,
        VaultRequest::GetEntry { id: id.to_string() },
    )?;
    if json || reveal {
        return emit(json, resp);
    }
    match resp {
        VaultResponse::Entry { entry } => {
            let has_password = !entry.password.is_empty();
            println!(
                "{}\t{}\t{}\thas_password={has_password}",
                entry.id, entry.name, entry.username
            );
            Ok(())
        }
        other => emit(false, other),
    }
}

fn rpc_stdio(paths: &AegisPaths, cbor: bool) -> Result<(), String> {
    if cbor {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        let req = VaultRequest::from_cbor(&buf).map_err(|e| format!("cbor request: {e}"))?;
        let resp = dispatch_auto(paths, req)?;
        let out = resp.to_cbor().map_err(|e| e.to_string())?;
        io::stdout().write_all(&out).map_err(|e| e.to_string())?;
        return Ok(());
    }
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let req = rpc::request_from_json(&line)?;
        let resp = dispatch_auto(paths, req)?;
        println!("{}", rpc::response_to_json(&resp)?);
    }
    Ok(())
}

fn read_passphrase(file: Option<&Path>, prompt: &str) -> Result<Zeroizing<String>, String> {
    match file {
        Some(p) if p.as_os_str() == "-" => {
            let mut s = String::new();
            io::stdin()
                .read_line(&mut s)
                .map_err(|e| e.to_string())?;
            while s.ends_with('\n') || s.ends_with('\r') {
                s.pop();
            }
            Ok(Zeroizing::new(s))
        }
        Some(p) => {
            let meta = fs::metadata(p).map_err(|e| e.to_string())?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "passphrase file {} must be mode 0600 (got {mode:o})",
                    p.display()
                ));
            }
            let mut s = fs::read_to_string(p).map_err(|e| e.to_string())?;
            while s.ends_with('\n') || s.ends_with('\r') {
                s.pop();
            }
            Ok(Zeroizing::new(s))
        }
        None if io::stdin().is_terminal() => rpassword::prompt_password(format!("{prompt}: "))
            .map(Zeroizing::new)
            .map_err(|e| e.to_string()),
        None => Err("passphrase required: use --passphrase-file or a tty".into()),
    }
}

fn json_str(path: &Path) -> String {
    serde_json::to_string(&path.to_string_lossy()).unwrap_or_else(|_| "\"\"".into())
}
