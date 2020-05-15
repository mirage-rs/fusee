mod status;

use termcolor::Color;

fn main() {
    info!("Searching", "for connected switch").unwrap();
    ok!("Found", "compatible device on port 1337").unwrap();
    info!("Preparing", "payload").unwrap();
    info!("Sending", "payload to the device").unwrap();
    error!("Failed", "to send to payload: cool error here").unwrap();
}
