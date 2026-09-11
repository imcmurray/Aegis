//! JSON-lines and length-prefixed CBOR on the agent socket.

use crate::paths::MAX_RPC_FRAME;
use aegis_common::crypto::Argon2ParamsV2;
use aegis_common::file_store::FileStore;
use aegis_common::messages::{VaultRequest, VaultResponse};
use aegis_common::session_v2::VaultSessionV2;
use aegis_common::sync::FileSyncTransport;
use aegis_common::vault::{dispatch_with_sync, ActiveSession};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

pub fn op_name(req: &VaultRequest) -> &'static str {
    match req {
        VaultRequest::CreateVault { .. } => "create_vault",
        VaultRequest::Unlock { .. } => "unlock",
        VaultRequest::Lock => "lock",
        VaultRequest::Status => "status",
        VaultRequest::ListSummaries { .. } => "list_summaries",
        VaultRequest::GetEntry { .. } => "get_entry",
        VaultRequest::UpsertEntry { .. } => "upsert_entry",
        VaultRequest::DeleteEntry { .. } => "delete_entry",
        VaultRequest::UpsertFolder { .. } => "upsert_folder",
        VaultRequest::DeleteFolder { .. } => "delete_folder",
        VaultRequest::ListFolders => "list_folders",
        VaultRequest::GeneratePassword { .. } => "generate_password",
        VaultRequest::GenerateTotp { .. } => "generate_totp",
        VaultRequest::ExportEncrypted { .. } => "export_encrypted",
        VaultRequest::ImportEncrypted { .. } => "import_encrypted",
        VaultRequest::PreviewImport { .. } => "preview_import",
        VaultRequest::GetAuditLog { .. } => "get_audit_log",
        VaultRequest::SyncNow => "sync_now",
        VaultRequest::SyncWithRemote { .. } => "sync_with_remote",
        VaultRequest::ChangePassphrase { .. } => "change_passphrase",
        VaultRequest::PasswordHealth => "password_health",
        VaultRequest::GenerateRecoveryKey { .. } => "generate_recovery_key",
        VaultRequest::ExportRecoveryKit => "export_recovery_kit",
        VaultRequest::ImportRecoveryKit { .. } => "import_recovery_kit",
        VaultRequest::UnlockWithRecovery { .. } => "unlock_with_recovery",
        VaultRequest::RevokeRecoveryKey => "revoke_recovery_key",
        VaultRequest::MigrateVault { .. } => "migrate_vault",
        VaultRequest::MigrateVaultWithRecovery { .. } => "migrate_vault_with_recovery",
        VaultRequest::RotateKeys { .. } => "rotate_keys",
        VaultRequest::ExportShareIdentity => "export_share_identity",
        VaultRequest::CreateShare { .. } => "create_share",
        VaultRequest::OpenShare { .. } => "open_share",
    }
}

pub fn handle(
    store: &mut FileStore,
    session: &mut Option<ActiveSession>,
    sync: &mut FileSyncTransport,
    req: VaultRequest,
) -> VaultResponse {
    tracing::info!(op = op_name(&req), "vault request");
    if crate::paths::test_kdf() {
        if let VaultRequest::CreateVault { passphrase, .. } = &req {
            return match VaultSessionV2::create_with_params(
                store,
                passphrase,
                Argon2ParamsV2::insecure_for_tests(),
            ) {
                Ok(s) => {
                    let vault_id = s.doc.meta.vault_id.clone();
                    *session = Some(ActiveSession::V2(s));
                    VaultResponse::Unlocked { vault_id }
                }
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            };
        }
    }
    dispatch_with_sync(store, session, req, Some(sync))
}

pub fn handle_state(state: &mut crate::agent::AppState, req: VaultRequest) -> VaultResponse {
    let crate::agent::AppState {
        store, session, sync, ..
    } = state;
    handle(store, session, sync, req)
}

pub fn write_frame(w: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_RPC_FRAME as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rpc frame too large",
        ));
    }
    let n = bytes.len() as u32;
    w.write_all(&n.to_le_bytes())?;
    w.write_all(bytes)?;
    w.flush()
}

pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let n = u32::from_le_bytes(len_buf);
    if n == 0 || n > MAX_RPC_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid rpc frame length",
        ));
    }
    let mut buf = vec![0u8; n as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn call_agent(sock: &std::path::Path, req: &VaultRequest) -> io::Result<VaultResponse> {
    let mut stream = UnixStream::connect(sock)?;
    let bytes = req
        .to_cbor()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(&mut stream, &bytes)?;
    let resp_bytes = read_frame(&mut stream)?;
    VaultResponse::from_cbor(&resp_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn request_from_json(line: &str) -> Result<VaultRequest, String> {
    serde_json::from_str(line).map_err(|e| format!("json request: {e}"))
}

pub fn response_to_json(resp: &VaultResponse) -> Result<String, String> {
    serde_json::to_string(resp).map_err(|e| format!("json response: {e}"))
}
