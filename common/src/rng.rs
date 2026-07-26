//! Platform RNG: OS / browser WebCrypto / Freenet host.

/// Fill `dest` with cryptographically secure random bytes.
pub fn fill_random(dest: &mut [u8]) {
    #[cfg(feature = "freenet-host")]
    {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            let bytes = freenet_stdlib::rand::rand_bytes(dest.len() as u32);
            dest.copy_from_slice(&bytes);
            return;
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            getrandom::getrandom(dest).expect("OS RNG failed");
            return;
        }
    }

    #[cfg(not(feature = "freenet-host"))]
    {
        getrandom::getrandom(dest).expect("RNG failed");
    }
}

/// Custom getrandom backend for Freenet WASM (used when `freenet-host` is enabled).
#[cfg(all(feature = "freenet-host", target_arch = "wasm32", target_os = "unknown"))]
pub fn freenet_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let bytes = freenet_stdlib::rand::rand_bytes(buf.len() as u32);
    buf.copy_from_slice(&bytes);
    Ok(())
}

#[cfg(all(feature = "freenet-host", target_arch = "wasm32", target_os = "unknown"))]
getrandom::register_custom_getrandom!(freenet_getrandom);
