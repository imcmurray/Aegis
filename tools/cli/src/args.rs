use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "aegis",
    version,
    about = "Aegis native vault CLI (file-backed production backend)"
)]
pub struct Cli {
    /// Print the JSON/CBOR protocol version and exit.
    #[arg(long)]
    pub protocol_version: bool,

    /// Vault data directory (default: $AEGIS_DATA or ~/.local/share/aegis).
    #[arg(long, global = true, env = "AEGIS_DATA")]
    pub data_dir: Option<PathBuf>,

    /// Runtime directory for the agent socket (default: $AEGIS_RUNTIME or $XDG_RUNTIME_DIR/aegis).
    #[arg(long, global = true, env = "AEGIS_RUNTIME")]
    pub runtime_dir: Option<PathBuf>,

    /// Machine-stable JSON on stdout (same `op` / `type` tags as VaultRequest / VaultResponse).
    #[arg(long, global = true)]
    pub json: bool,

    /// Read a passphrase from this file (mode 0600) or `-` for stdin. Never argv.
    #[arg(long, global = true)]
    pub passphrase_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Status,
    Create,
    Unlock,
    Lock,
    Agent(AgentCmd),
    Search {
        query: Option<String>,
    },
    Folders,
    Generate,
    Copy {
        id_or_query: String,
        #[arg(long, value_enum, default_value = "password")]
        field: CopyField,
        /// Write the secret to stdout instead of the clipboard.
        #[arg(long)]
        stdout: bool,
        /// Do not wipe the clipboard after 30 seconds.
        #[arg(long)]
        no_clear: bool,
    },
    Totp {
        id_or_query: String,
    },
    Get {
        id: String,
        /// Print secrets in text mode (default is --json only).
        #[arg(long)]
        reveal: bool,
    },
    Export {
        path: PathBuf,
        #[arg(long)]
        backup_passphrase_file: Option<PathBuf>,
    },
    Import {
        path: PathBuf,
        #[arg(long)]
        preview: bool,
        /// Wipe an existing vault and restore this backup as a **new** live
        /// identity (new vault_id). Default refuses if a vault is already
        /// present. D18 still requires a new live passphrase. Not Recovery Kit
        /// identity-preserving restore. Conflicts with --preview.
        #[arg(long, conflicts_with = "preview")]
        replace: bool,
        #[arg(long)]
        backup_passphrase_file: Option<PathBuf>,
        #[arg(long)]
        new_passphrase_file: Option<PathBuf>,
    },
    Rpc {
        /// Raw CBOR VaultRequest on stdin, CBOR VaultResponse on stdout.
        #[arg(long)]
        cbor: bool,
    },
    /// Internal: wipe clipboard after a delay. Not part of the user surface.
    #[command(hide = true, name = "__wipe-clipboard")]
    WipeClipboard {
        #[arg(long)]
        seconds: u64,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CopyField {
    Password,
    Username,
    Totp,
    Url,
}

#[derive(Debug, Parser)]
pub struct AgentCmd {
    #[command(subcommand)]
    pub action: Option<AgentAction>,
    /// Stay in this process (do not detach).
    #[arg(long, global = true)]
    pub foreground: bool,
    /// Auto-lock idle seconds (default 300).
    #[arg(long, global = true, default_value_t = 300)]
    pub lock_after: u64,
}

#[derive(Debug, Subcommand)]
pub enum AgentAction {
    Status,
    Stop,
}
