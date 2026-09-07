#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegis_common::crypto::MasterEnvelopeV2::from_bytes(data);
});
