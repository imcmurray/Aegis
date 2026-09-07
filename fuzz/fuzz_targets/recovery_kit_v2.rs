#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegis_common::recovery_v2::RecoveryWrapV2::from_kit_bytes(data);
});
