#![deny(rust_2018_idioms, broken_intra_doc_links)]

mod macros;

use fusee::usb::{get_rcm_device, Rcm};
use std::{path::PathBuf, thread, time::Duration};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("to read the device id.")]
    InvalidDeviceId,
    #[error("to access device: Permission denied.")]
    PermissionDenied,
    #[error("to find a Switch in RCM mode.")]
    NoDevice,
    #[error("to inject payload: Payload already injected.")]
    AlreadyInjected,
    #[error("because the payload was to big.")]
    PayloadTooBig,
    #[error("due to an I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("due an unknown usb error: {0}")]
    UnknownUsbError(#[from] rusb::Error),
}

/// Fusee Gelee exploit Launcher for the Nintendo Switch.
#[derive(argh::FromArgs)]
struct Arguments {
    /// wait until a Switch in RCM mode is available.
    #[argh(switch, short = 'w')]
    wait: bool,

    /// override the TegraRCM vendor ID.
    #[argh(option, short = 'V')]
    vendor_id: Option<u16>,
    /// override the TegraRCM product ID.
    #[argh(option, short = 'P')]
    product_id: Option<u16>,

    /// path the payload binary which will be executed on the Switch.
    #[argh(positional)]
    payload: PathBuf,
}

fn main() {
    let args = argh::from_env::<Arguments>();
    match inject(args) {
        Ok(_) => {}
        Err(err) => {
            error!("Failed", "{}", err);
            std::process::exit(1);
        }
    }
}

fn inject(args: Arguments) -> Result<(), Error> {
    info!("Reading", "payload from {:?}...", args.payload);
    let payload = std::fs::read(&args.payload)?;
    ok!("Read", "payload from {:?}", args.payload);
    let payload = fusee::build_payload(payload).ok_or(Error::PayloadTooBig)?;

    info!("Searching", "for a Switch in RCM mode...");
    let mut dev = find_rcm_device(args.wait, args.vendor_id, args.product_id)?;

    let dev_id = dev.read_device_id().ok_or(Error::InvalidDeviceId)?;
    info!("Found", "compatible Switch with id {:?}", dev_id);

    info!("Exploiting", "the Switch...");
    dev.write(&payload)?;
    dev.switch_dma_buffer(true)?;
    let _ = dev.memecpy().unwrap();
    ok!("Successfully", "exploited the Switch.");

    Ok(())
}

fn find_rcm_device(wait: bool, vid: Option<u16>, pid: Option<u16>) -> Result<Rcm, Error> {
    let get_device = || match get_rcm_device(vid, pid) {
        Ok(dev) => Ok(Rcm::new(dev)),
        Err(rusb::Error::Access) => Err(Error::PermissionDenied),
        Err(rusb::Error::NoDevice) => Err(Error::NoDevice),
        Err(rusb::Error::Busy) | Err(rusb::Error::Timeout) => Err(Error::AlreadyInjected),
        Err(e) => Err(e.into()),
    };

    let mut device = get_device();
    while wait {
        device = match device {
            Ok(_) => break,
            Err(Error::NoDevice) => {
                thread::sleep(Duration::from_millis(500));
                get_device()
            }
            Err(err) => return Err(err),
        }
    }

    device
}
