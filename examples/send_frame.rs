//! Example: send a raw frame using the library API without clap.
//!
//! ```sh
//! # Generate a 32-byte key first:
//! dd if=/dev/urandom of=psk.bin bs=32 count=1
//!
//! # Run this example:
//! cargo run --example send_frame
//! ```

use std::net::Ipv4Addr;

use fiudp_cli::{Config, FiudpError, run};

fn main() {
    let config = Config::builder()
        .target(Ipv4Addr::new(192, 168, 1, 42))
        .wake_at(3600)
        .key_file("./psk.bin")
        .image("./frame.raw")
        .parity_ratio(20)
        .build()
        .expect("invalid config");

    match run(config) {
        Ok(()) => println!("Frame sent successfully."),
        Err(FiudpError::EmptyInput) => {
            eprintln!("Error: input file is empty.");
            std::process::exit(1);
        }
        Err(FiudpError::Io { context, source }) => {
            eprintln!("I/O error ({context}): {source}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}
