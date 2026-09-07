//! Aegis shared library: types, cryptography, vault session logic, and UI↔delegate messages.

pub mod crypto;
pub mod crdt;
pub mod file_store;
pub mod gen_store;
pub mod health;
pub mod messages;
pub mod migrate;
pub mod recovery_v2;
pub mod rng;
pub mod session_v2;
pub mod share;
pub mod sync;
pub mod sync_types;
pub mod sync_v2;
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

#[cfg(test)]
#[path = "../tests/v1_compat.rs"]
mod v1_compat_tests;

#[cfg(test)]
#[path = "../tests/phase5.rs"]
mod phase5_tests;

#[cfg(test)]
#[path = "../tests/phase6.rs"]
mod phase6_tests;

#[cfg(test)]
#[path = "../tests/phase7.rs"]
mod phase7_tests;

#[cfg(test)]
#[path = "../tests/mldsa_acvp.rs"]
mod mldsa_acvp_tests;

#[cfg(test)]
#[path = "../tests/phase8.rs"]
mod phase8_tests;

#[cfg(test)]
#[path = "../tests/mlkem_acvp.rs"]
mod mlkem_acvp_tests;

#[cfg(test)]
#[path = "../tests/phase9.rs"]
mod phase9_tests;

#[cfg(test)]
#[path = "../tests/phase10.rs"]
mod phase10_tests;
