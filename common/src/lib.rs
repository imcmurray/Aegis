//! Aegis shared library: types, cryptography, vault session logic, and UI↔delegate messages.

pub mod crypto;
pub mod crdt;
pub mod file_store;
pub mod health;
pub mod messages;
pub mod rng;
pub mod sync;
pub mod sync_types;
pub mod totp;
pub mod types;
pub mod vault;

pub use crypto::{
    derive_keys, generate_password, generate_recovery_key_display, normalize_recovery_key, open,
    seal, unwrap_master, wrap_existing_master, wrap_master, DerivedKeys, EnvelopeKind,
    GeneratorPolicy, KdfParams, KdfProfile, MasterEnvelope, SealedBlob, AEGIS_DOMAIN,
};
pub use messages::{ErrorCode, VaultRequest, VaultResponse};
pub use types::*;
pub use vault::{VaultError, VaultSession};
