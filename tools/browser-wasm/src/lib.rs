//! Browser vault: same crypto as the Freenet delegate / dev server, no peer required.
//!
//! Persistence is owned by JS (IndexedDB): call `export_store` after mutations
//! and `import_store` on load. Session key is never exported.

use aegis_common::messages::{VaultRequest, VaultResponse};
use aegis_common::vault::{dispatch, MemoryStore, SecretStore, VaultSession};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct BrowserVault {
    store: MemoryStore,
    session: Option<VaultSession>,
}

#[wasm_bindgen]
impl BrowserVault {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook::set_once();
        Self {
            store: MemoryStore::default(),
            session: None,
        }
    }

    /// CBOR `VaultRequest` in → CBOR `VaultResponse` out.
    pub fn request(&mut self, req_cbor: &[u8]) -> Vec<u8> {
        let req = match VaultRequest::from_cbor(req_cbor) {
            Ok(r) => r,
            Err(e) => {
                return VaultResponse::err(
                    aegis_common::messages::ErrorCode::Internal,
                    format!("bad request: {e}"),
                )
                .to_cbor()
                .unwrap_or_default();
            }
        };
        let resp = dispatch(&mut self.store, &mut self.session, req);
        // Keep session master in store while unlocked (delegate pattern).
        match &self.session {
            Some(s) => {
                self.store
                    .set(aegis_common::vault::SECRET_SESSION, s.master.as_bytes());
            }
            None => {
                if self.store.has(aegis_common::vault::SECRET_SESSION) {
                    self.store.remove(aegis_common::vault::SECRET_SESSION);
                }
            }
        }
        resp.to_cbor().unwrap_or_else(|e| {
            VaultResponse::err(
                aegis_common::messages::ErrorCode::Internal,
                format!("encode: {e}"),
            )
            .to_cbor()
            .unwrap_or_default()
        })
    }

    /// Durable secrets for IndexedDB (excludes unlocked session key).
    pub fn export_store(&self) -> Vec<u8> {
        self.store.export_cbor_skip_session().unwrap_or_default()
    }

    /// Load secrets from IndexedDB (locked vault; user still unlocks).
    pub fn import_store(&mut self, bytes: &[u8]) {
        let _ = self.store.import_cbor(bytes);
        self.session = None;
    }
}

impl Default for BrowserVault {
    fn default() -> Self {
        Self::new()
    }
}
