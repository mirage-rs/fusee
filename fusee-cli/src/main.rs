mod error;
mod status;

use error::FuseeError;
use fusee::usb::{get_rcm_device, Rcm};
use fusee::rusb;

fn main() {
    match execute() {
        Ok(()) => {}
        Err(err) => error!("Failed", "{}", err),
    }
}

fn execute() -> Result<(), FuseeError> {
    info!("Searching", "for a Switch in RCM mode...");
    let dev = match get_rcm_device(None, None) {
        Ok(dev) => Rcm::new(dev),
        Err(rusb::Error::Access) => return Err(FuseeError::PermissionDenied),
        Err(rusb::Error::NoDevice) => return Err(FuseeError::NoDevice),
        Err(rusb::Error::Busy) | Err(rusb::Error::Timeout) => return Err(FuseeError::AlreadyInjected),
        Err(e) => return Err(e.into()),
    };
    let dev_id = dev.read_device_id().ok_or(FuseeError::InvalidDeviceId)?;

    info!("Found", "compatible Switch with id {:?}", dev_id);

    Ok(())
}
