use rusb::{Device, DeviceHandle, Result};

const DEFAULT_VENDOR_ID: u16 = 0x0955;
const DEFAULT_PRODUCT_ID: u16 = 0x0955;

struct UsbWriter {
    vendor_id: u16,
    product_id: u16,
}

impl UsbWriter {
    pub fn new() -> Self {
        Self::new(DEFAULT_VENDOR_ID, DEFAULT_PRODUCT_ID)
    }

    /*
     *fn find_open_device(&self) -> Result {
     *    for device in rusb::devices()?.iter() {
     *        let desc = device.device_descriptor()?;
     *    }
     *    Err(rusb::Error::NotFound);
     *}
     */
}
