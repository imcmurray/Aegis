//! Aegis Vault Delegate
//!
//! Holds encrypted vault material in the Freenet secret store and performs
//! all cryptographic operations. The UI never sees MasterSecret or DEK bytes.

#![allow(dead_code)] // referenced via #[delegate] WASM export path

use aegis_common::delegate_session::{process_message, SessionOrigin};
use aegis_common::gen_store::GenerationStore;
use aegis_common::types::unix_now;
use aegis_common::vault::{
    SecretStore, UNSUPPORTED_ATOMIC_COMMIT, SECRET_AUDIT, SECRET_ENVELOPE, SECRET_VAULT,
};
use freenet_stdlib::prelude::*;

/// Adapter: Freenet DelegateCtx → SecretStore.
struct CtxStore<'a> {
    ctx: &'a mut DelegateCtx,
}

impl SecretStore for CtxStore<'_> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.ctx.get_secret(key)
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.ctx.set_secret(key, value);
    }

    fn remove(&mut self, key: &[u8]) {
        // DelegateCtx may not expose remove on all versions; overwrite with empty + best effort.
        if self.ctx.has_secret(key) {
            // Prefer remove_secret when available.
            self.ctx.remove_secret(key);
        }
    }

    fn has(&self, key: &[u8]) -> bool {
        self.ctx.has_secret(key)
    }

    fn commit(
        &mut self,
        _ops: &[aegis_common::vault::StoreOp],
    ) -> Result<(), String> {
        // Single-key set_secret is assumed durable; multi-key sequential write is not
        // a commit. Callers must wrap this adapter in GenerationStore.
        Err(UNSUPPORTED_ATOMIC_COMMIT.into())
    }
}

struct Delegate;

fn respond(payload: Vec<u8>) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(payload).processed(true),
    )])
}

/// Map the Freenet message origin to the session-token origin binding.
#[allow(unreachable_patterns)]
fn session_origin(origin: &Option<MessageOrigin>) -> SessionOrigin {
    match origin {
        Some(MessageOrigin::WebApp(id)) => match <[u8; 32]>::try_from(id.as_bytes()) {
            Ok(bytes) => SessionOrigin::WebApp(bytes),
            Err(_) => SessionOrigin::Other,
        },
        _ => SessionOrigin::Other,
    }
}

fn fill_random(buf: &mut [u8]) {
    aegis_common::rng::fill_random(buf);
}

#[delegate]
impl DelegateInterface for Delegate {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        match message {
            InboundDelegateMsg::ApplicationMessage(app_msg) => {
                let origin = session_origin(&origin);
                let mut store = GenerationStore::new(CtxStore { ctx });
                let out = process_message(
                    &mut store,
                    &app_msg.payload,
                    unix_now(),
                    &origin,
                    &mut |b| fill_random(b),
                )
                .map_err(DelegateError::Deser)?;

                // Touch keys so the compiler knows we intend to use them (documentation).
                let _ = (SECRET_ENVELOPE, SECRET_VAULT, SECRET_AUDIT);

                respond(out)
            }
            InboundDelegateMsg::UserResponse(_) => {
                // Future: confirm export / share consent.
                Ok(vec![])
            }
            _ => Ok(vec![]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::crypto::KdfProfile;
    use aegis_common::messages::{VaultRequest, VaultResponse};
    use aegis_common::vault::{dispatch, MemoryStore};

    #[test]
    fn dispatch_via_memory_store() {
        let mut store = MemoryStore::default();
        let mut session = None;
        let resp = dispatch(
            &mut store,
            &mut session,
            VaultRequest::CreateVault {
                passphrase: "correct horse battery staple".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        assert!(matches!(resp, VaultResponse::Unlocked { .. }));
        assert!(store.has(aegis_common::session_v2::SECRET_ENVELOPE_V2));
        assert!(store.has(aegis_common::session_v2::SECRET_VAULT_V2));
    }
}
