use bytes::Bytes;
use clap::{crate_authors, crate_description, crate_version, App, Arg};
use std::{
    error::Error,
    fs::File,
    io::{prelude::*, BufReader},
};

fn main() {
    let result = run();
    if result.is_err() {
        eprintln!("error: {}", result.unwrap_err());
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let matches = App::new("fusee")
        .about(crate_description!())
        .author(crate_authors!())
        .version(crate_version!())
        .arg(
            Arg::with_name("payload")
                .index(1)
                .required(true)
                .help("ARM payload to be launched, should be linked at 0x4001000"),
        )
        .get_matches();

    let file_name = matches.value_of("payload").unwrap();
    let file: File =
        File::open(file_name).map_err(|err| format!("failed to open payload file: {}", err))?;

    let mut reader = BufReader::new(file);
    let mut payload = Vec::new();
    reader
        .read_to_end(&mut payload)
        .map_err(|err| format!("failed to read payload file: {}", err))?;

    let _payload = fusee::build_payload(Bytes::from(payload));

    // TODO: Write to usb

    Ok(())
}
