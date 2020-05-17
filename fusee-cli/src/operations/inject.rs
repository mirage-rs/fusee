use crate::{app::*, error::FuseeError, info, ok};
use fusee::{
    rusb,
    usb::{get_rcm_device, Rcm},
};
use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::PathBuf,
    thread,
    time::Duration,
};

pub fn do_inject(options: InjectOptions) -> Result<(), FuseeError> {
    info!("Reading", "payload from {:?}...", options.payload);
    let payload = read_payload_file(&options.payload)?;
    ok!("Read", "payload from {:?}", options.payload);
    let payload = fusee::build_payload(payload.into());

    info!("Searching", "for a Switch in RCM mode...");
    let mut dev = if options.wait {
        wait_for_device()?
    } else {
        find_rcm_device()?
    };

    let dev_id = dev.read_device_id().ok_or(FuseeError::InvalidDeviceId)?;
    info!("Found", "compatible Switch with id {:?}", dev_id);

    info!("Exploiting", "the Switch...");
    dev.write(&payload)?;
    dev.switch_dma_buffer(true)?;
    let _ = dev.memecpy();
    ok!("Successfully", "exploited the Switch.");

    Ok(())
}

fn read_payload_file(path: &PathBuf) -> Result<Vec<u8>, FuseeError> {
    let read = File::open(path)?;
    let mut read = BufReader::new(read);
    let mut buf = Vec::new();
    read.read_to_end(&mut buf)?;
    Ok(buf)
}

fn wait_for_device() -> Result<Rcm, FuseeError> {
    loop {
        match find_rcm_device() {
            Ok(dev) => return Ok(dev),
            Err(FuseeError::NoDevice) => {}
            Err(e) => return Err(e),
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn find_rcm_device() -> Result<Rcm, FuseeError> {
    match get_rcm_device(None, None) {
        Ok(dev) => Ok(Rcm::new(dev)),
        Err(rusb::Error::Access) => Err(FuseeError::PermissionDenied),
        Err(rusb::Error::NoDevice) => Err(FuseeError::NoDevice),
        Err(rusb::Error::Busy) | Err(rusb::Error::Timeout) => Err(FuseeError::AlreadyInjected),
        Err(e) => Err(e.into()),
    }
}
