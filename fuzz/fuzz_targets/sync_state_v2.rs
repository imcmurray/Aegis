#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegis_common::sync_v2::decode_state_v2(data);
});
