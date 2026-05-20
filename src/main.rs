use std::process;

use clap::Parser;

use fiudp_cli::{run, Args, Config};

fn main() {
    let args = Args::parse();
    let config = match Config::try_from(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };
    if let Err(e) = run(config) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
