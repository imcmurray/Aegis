//! Local dev vault server.
//!
//! Speaks the same CBOR `VaultRequest` / `VaultResponse` protocol as the
//! Freenet vault-delegate, over HTTP, using in-process `aegis-common` crypto.
//!
//!   GET  /              — help page
//!   GET  /health
//!   POST /v1/vault      — CBOR VaultRequest → VaultResponse
//!
//! Data dir (encrypted vault blobs + sync state):
//!   $AEGIS_DEV_DATA  or  ~/.local/share/aegis-dev
//!
//! Run:
//!   cargo run -p aegis-dev-vault-server
//!
//! UI:
//!   cd ui && npm run dev
//!   http://localhost:5173/?mode=dev

use aegis_common::file_store::FileStore;
use aegis_common::messages::{VaultRequest, VaultResponse};
use aegis_common::sync::FileSyncTransport;
use aegis_common::vault::{dispatch_with_sync, VaultSession};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

struct AppState {
    store: FileStore,
    session: Option<VaultSession>,
    sync: FileSyncTransport,
    data_dir: PathBuf,
}

type Shared = Arc<Mutex<AppState>>;

fn listen_addr() -> SocketAddr {
    if let Ok(s) = std::env::var("AEGIS_DEV_ADDR") {
        return s
            .parse()
            .unwrap_or_else(|e| panic!("invalid AEGIS_DEV_ADDR={s:?}: {e}"));
    }
    let port: u16 = std::env::var("AEGIS_DEV_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8787);
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("AEGIS_DEV_DATA") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".local/share/aegis-dev")
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_dev_vault_server=info".into()),
        )
        .init();

    let data_dir = data_dir();
    let store = FileStore::open(data_dir.join("secrets"))
        .unwrap_or_else(|e| panic!("cannot open vault data dir: {e}"));
    let sync = FileSyncTransport::open(data_dir.join("sync").join("vault_sync.cbor"));

    tracing::info!("data dir: {}", data_dir.display());

    let state = Arc::new(Mutex::new(AppState {
        store,
        session: None,
        sync,
        data_dir: data_dir.clone(),
    }));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/v1/vault", post(vault))
        .layer(cors)
        .with_state(state);

    let addr = listen_addr();
    tracing::info!("Aegis dev vault server binding http://{addr}");
    tracing::info!("  POST /v1/vault  (application/cbor)");
    tracing::info!("  UI: http://localhost:5173/?mode=dev");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!(
                "error: address {addr} is already in use.\n\
                 \n\
                 Free the port:  ss -ltnp | grep {port}   then kill <pid>\n\
                 Or:  AEGIS_DEV_PORT=8788 cargo run -p aegis-dev-vault-server\n",
                port = addr.port(),
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!("listening on http://{addr}");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("error: server exited: {e}");
        std::process::exit(1);
    }
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn index(State(state): State<Shared>) -> impl IntoResponse {
    let dir = {
        let g = state.lock().await;
        g.data_dir.display().to_string()
    };
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Aegis dev vault API</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 42rem; margin: 2rem auto; padding: 0 1rem;
           background: #0f1419; color: #e7ecf3; line-height: 1.5; }}
    a {{ color: #3d9cf0; }}
    code, pre {{ background: #1a2332; padding: 0.15rem 0.4rem; border-radius: 4px; }}
    pre {{ padding: 0.75rem 1rem; overflow-x: auto; }}
    .ok {{ color: #7fd962; }}
  </style>
</head>
<body>
  <h1>Aegis dev vault <span class="ok">API</span></h1>
  <p>This is the <em>Rust crypto backend</em> (not the UI).</p>
  <h2>Open the UI</h2>
  <ol>
    <li><pre>cd ui &amp;&amp; npm run dev</pre></li>
    <li><a href="http://localhost:5173/?mode=dev">http://localhost:5173/?mode=dev</a></li>
  </ol>
  <p>Data directory: <code>{dir}</code></p>
  <p>Vault ciphertext + multi-device sync state are stored here (encrypted).</p>
  <h2>API</h2>
  <ul>
    <li><a href="/health"><code>GET /health</code></a></li>
    <li><code>POST /v1/vault</code> — CBOR</li>
  </ul>
</body>
</html>"#,
        dir = html_escape(&dir),
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

async fn vault(State(state): State<Shared>, body: Bytes) -> Response {
    let req = match VaultRequest::from_cbor(&body) {
        Ok(r) => r,
        Err(e) => {
            let resp = VaultResponse::err(
                aegis_common::messages::ErrorCode::InvalidRequest,
                format!("bad cbor request: {e}"),
            );
            return cbor_response(StatusCode::BAD_REQUEST, &resp);
        }
    };

    let op = match &req {
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
        VaultRequest::GetAuditLog { .. } => "get_audit_log",
        VaultRequest::SyncNow => "sync_now",
        VaultRequest::SyncWithRemote { .. } => "sync_with_remote",
        VaultRequest::ChangePassphrase { .. } => "change_passphrase",
        VaultRequest::PasswordHealth => "password_health",
        VaultRequest::GenerateRecoveryKey { .. } => "generate_recovery_key",
        VaultRequest::UnlockWithRecovery { .. } => "unlock_with_recovery",
        VaultRequest::RevokeRecoveryKey => "revoke_recovery_key",
    };
    tracing::info!(op, "vault request");

    let mut guard = state.lock().await;
    let AppState {
        store,
        session,
        sync,
        ..
    } = &mut *guard;
    let resp = dispatch_with_sync(store, session, req, Some(sync));
    cbor_response(StatusCode::OK, &resp)
}

fn cbor_response(status: StatusCode, resp: &VaultResponse) -> Response {
    match resp.to_cbor() {
        Ok(bytes) => (
            status,
            [(header::CONTENT_TYPE, "application/cbor")],
            bytes,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(%e, "failed to encode response");
            (StatusCode::INTERNAL_SERVER_ERROR, "encode error").into_response()
        }
    }
}
