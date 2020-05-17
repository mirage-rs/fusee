use thiserror::Error;

#[derive(Error, Debug)]
pub enum FuseeError {
    #[error("to read the device id.")]
    InvalidDeviceId,
    #[error("to access device: Permission denied.")]
    PermissionDenied,
    #[error("to find a Switch in RCM mode.")]
    NoDevice,
    #[error("to inject payload: Payload already injected.")]
    AlreadyInjected,
    #[error("due to an I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("due an unknown usb error: {0}")]
    UnknownUsbError(#[from] fusee::rusb::Error),
}
