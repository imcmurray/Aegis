//! Aegis Vault Delegate
//!
//! Holds encrypted vault material in the Freenet secret store and performs
//! all cryptographic operations. The UI never sees MasterSecret or DEK bytes.

#![allow(dead_code)] // referenced via #[delegate] WASM export path

use aegis_common::messages::{VaultRequest, VaultResponse};
use aegis_common::vault::{
    dispatch, SecretStore, VaultSession, SECRET_AUDIT, SECRET_ENVELOPE, SECRET_SESSION, SECRET_VAULT,
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
}

struct Delegate;

fn respond(resp: VaultResponse) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let payload = resp
        .to_cbor()
        .map_err(|e| DelegateError::Deser(e))?;
    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(payload).processed(true),
    )])
}

fn load_session(store: &dyn SecretStore) -> Option<VaultSession> {
    VaultSession::try_resume(store).ok().flatten()
}

#[delegate]
impl DelegateInterface for Delegate {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        _origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        match message {
            InboundDelegateMsg::ApplicationMessage(app_msg) => {
                let req = VaultRequest::from_cbor(&app_msg.payload)
                    .map_err(|e| DelegateError::Deser(e))?;

                let mut store = CtxStore { ctx };
                let mut session = load_session(&store);
                let resp = dispatch(&mut store, &mut session, req);

                // Ensure session secret is consistent after dispatch.
                match &session {
                    Some(s) => {
                        store.set(SECRET_SESSION, s.master.as_bytes());
                    }
                    None => {
                        if store.has(SECRET_SESSION) {
                            store.remove(SECRET_SESSION);
                        }
                    }
                }

                // Touch keys so the compiler knows we intend to use them (documentation).
                let _ = (SECRET_ENVELOPE, SECRET_VAULT, SECRET_AUDIT);

                respond(resp)
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
    use aegis_common::vault::MemoryStore;

    #[test]
    fn dispatch_via_memory_store() {
        let mut store = MemoryStore::default();
        let mut session = None;
        let resp = dispatch(
            &mut store,
            &mut session,
            VaultRequest::CreateVault {
                passphrase: "delegate-test".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        assert!(matches!(resp, VaultResponse::Unlocked { .. }));
        assert!(store.has(SECRET_ENVELOPE));
        assert!(store.has(SECRET_VAULT));
    }
}
