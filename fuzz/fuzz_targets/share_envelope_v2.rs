#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegis_common::share::ShareEnvelopeV2::from_cbor(data);
});
