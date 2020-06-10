extern crate bindgen;

use std::env;
use std::path::PathBuf;

use bindgen::callbacks::{IntKind, ParseCallbacks};

#[derive(Debug)]
struct Parse;

impl ParseCallbacks for Parse {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        if name.starts_with("USBDEVFS_URB_TYPE_") {
            Some(bindgen::callbacks::IntKind::U8)
        } else {
            None
        }
    }
}

fn generate_bindings() {
    // Generate Rust bindings to usbdevice_fs.h header.
    let bindings = bindgen::Builder::default()
        .header("/usr/include/linux/usbdevice_fs.h")
        .generate_comments(true)
        .whitelist_type("^usbdevfs.*")
        .whitelist_function("^usbdevfs.*")
        .whitelist_var("^USBDEVFS.*")
        .parse_callbacks(Box::new(Parse))
        .generate()
        .expect("Failed to generate bindings");

    // Write bindings to output file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings to output file");
}

fn main() {
    #[cfg(target_os = "linux")]
    generate_bindings();
}
