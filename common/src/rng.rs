//! Platform RNG: OS / browser WebCrypto / Freenet host.
//!
//! On wasm32-unknown-unknown exactly one of the `browser` and `freenet-host`
//! features must be enabled. Freenet builds take all randomness (getrandom 0.2
//! and getrandom 0.4 paths) from `freenet_stdlib::rand`; browser builds use
//! WebCrypto through getrandom's `js` / `wasm_js` backends.

#[cfg(all(
    target_arch = "wasm32",
    target_os = "unknown",
    feature = "browser",
    feature = "freenet-host"
))]
compile_error!(
    "aegis-common: features `browser` and `freenet-host` are mutually exclusive on \
     wasm32-unknown-unknown (feature unification would let getrandom's JS backend \
     override the Freenet host RNG). Build each WASM crate with its own \
     `cargo build -p <crate>` command, never a combined `--workspace` wasm build."
);

#[cfg(all(
    target_arch = "wasm32",
    target_os = "unknown",
    not(feature = "browser"),
    not(feature = "freenet-host")
))]
compile_error!(
    "aegis-common on wasm32-unknown-unknown needs feature `browser` (browser WASM) or \
     `freenet-host` (Freenet contract/delegate WASM); enable exactly one."
);

#[cfg(all(
    target_arch = "wasm32",
    target_os = "unknown",
    feature = "freenet-host",
    not(getrandom_backend = "custom")
))]
compile_error!(
    "aegis-common `freenet-host` on wasm32-unknown-unknown requires \
     --cfg getrandom_backend=\"custom\" (the default in .cargo/config.toml). Do not \
     override RUSTFLAGS for Freenet builds."
);

#[cfg(all(
    target_arch = "wasm32",
    target_os = "unknown",
    feature = "browser",
    not(getrandom_backend = "wasm_js")
))]
compile_error!(
    "aegis-common `browser` on wasm32-unknown-unknown requires \
     RUSTFLAGS='--cfg getrandom_backend=\"wasm_js\"' (see scripts/build-wasm.sh); \
     .cargo/config.toml defaults to the Freenet `custom` backend."
);

/// Fill `dest` with random bytes from the Freenet host RNG.
///
/// Panics if the host returns a different number of bytes than requested:
/// never truncates or zero-pads. An empty `dest` is valid.
#[cfg(all(feature = "freenet-host", target_arch = "wasm32", target_os = "unknown"))]
fn freenet_host_fill(dest: &mut [u8]) {
    if dest.is_empty() {
        return;
    }
    let bytes = freenet_stdlib::rand::rand_bytes(dest.len() as u32);
    assert_eq!(
        bytes.len(),
        dest.len(),
        "Freenet host RNG returned {} bytes, expected {}",
        bytes.len(),
        dest.len()
    );
    dest.copy_from_slice(&bytes);
}

/// Fill `dest` with cryptographically secure random bytes.
pub fn fill_random(dest: &mut [u8]) {
    #[cfg(all(feature = "freenet-host", target_arch = "wasm32", target_os = "unknown"))]
    {
        freenet_host_fill(dest);
    }

    #[cfg(not(all(feature = "freenet-host", target_arch = "wasm32", target_os = "unknown")))]
    {
        getrandom::getrandom(dest).expect("RNG failed");
    }
}

/// Custom getrandom 0.2 backend for Freenet WASM (used when `freenet-host` is enabled).
#[cfg(all(feature = "freenet-host", target_arch = "wasm32", target_os = "unknown"))]
pub fn freenet_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    freenet_host_fill(buf);
    Ok(())
}

#[cfg(all(feature = "freenet-host", target_arch = "wasm32", target_os = "unknown"))]
getrandom::register_custom_getrandom!(freenet_getrandom);

/// Custom getrandom 0.4 backend (`getrandom_backend="custom"`), pulled in via
/// crypto-common from ml-dsa / ml-kem default features.
///
/// # Safety
/// Called by getrandom with a valid, writable `dest` of `len` bytes.
#[cfg(all(feature = "freenet-host", target_arch = "wasm32", target_os = "unknown"))]
#[no_mangle]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom_04::Error> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: getrandom guarantees `dest` points to `len` writable bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(dest, len) };
    freenet_host_fill(buf);
    Ok(())
}
