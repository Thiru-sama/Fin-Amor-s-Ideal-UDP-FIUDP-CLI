use anyhow::Result;
use clap::Parser;

use fiudp_cli::{run, Args, Config};

fn main() -> Result<()> {
    let args = Args::parse();
    let config = Config::try_from(args)?;
    run(config)
}
