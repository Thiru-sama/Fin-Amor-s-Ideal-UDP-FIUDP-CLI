//! CLI arguments, validated configuration, and builder.
//!
//! This module contains everything related to configuring the FIUDP
//! sender before it runs:
//!
//! - [`Args`] — the raw CLI argument struct (derives [`clap::Parser`]).
//! - [`Config`] — the validated, type-safe configuration consumed by
//!   [`crate::run`].
//! - [`ConfigBuilder`] — a programmatic builder for [`Config`] that
//!   does not require clap parsing.
//! - [`ParityRatio`] — a validated percentage (0–100) used to compute
//!   the number of parity shards.
//! - [`InputSource`] / [`InputReader`] — abstraction over file and
//!   stdin input.

use std::fs;
use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use crate::error::{FiudpError, Result};

/// Default UDP port for the FIUDP receiver (see SPEC.md §3.1).
const DEFAULT_UDP_PORT: u16 = 5050;

/// Default inter-packet delay in microseconds.
///
/// A small delay between consecutive sends prevents overwhelming the
/// receiver's radio or causing excessive packet loss on congested links.
const DEFAULT_INTER_PACKET_DELAY_US: u64 = 500;

// -----------------------------------------------------------------------
// CLI arguments
// -----------------------------------------------------------------------

/// Command-line arguments for the FIUDP sender.
///
/// This struct derives [`clap::Parser`] and maps directly to the CLI flags
/// documented in the project README. Use [`Config::try_from`] to validate
/// and convert these arguments into a [`Config`] suitable for [`crate::run`].
///
/// # Example
///
/// ```rust,no_run
/// use clap::Parser;
/// use fiudp_cli::Args;
///
/// let args = Args::parse();
/// ```
#[derive(Parser, Debug)]
#[command(name = "fiudp-cli", version, about = "FIUDP unidirectional UDP sender")]
pub struct Args {
    /// Target IPv4 address of the TRMNL display.
    #[arg(short = 't', long = "target", alias = "ip", value_name = "IP")]
    target: Ipv4Addr,

    /// Wake-up timer in seconds for the next sync cycle.
    #[arg(
        short = 'w',
        long = "wake-at",
        alias = "rendezvous",
        value_name = "SECS"
    )]
    wake_at: u32,

    /// Path to the 256-bit (32 bytes) pre-shared key file.
    #[arg(short = 'k', long = "key-file", value_name = "FILE")]
    key_file: PathBuf,

    /// Path to the raw input buffer file (fallback to STDIN if omitted).
    #[arg(short = 'i', long = "image", alias = "input", value_name = "FILE")]
    image: Option<PathBuf>,

    /// Percentage of parity shards to generate (0–100).
    #[arg(
        short = 'p',
        long = "parity-ratio",
        default_value_t = 15,
        value_name = "PERCENT"
    )]
    parity_ratio: u8,

    /// UDP port of the TRMNL receiver.
    #[arg(long, default_value_t = DEFAULT_UDP_PORT)]
    port: u16,

    /// Delay between packets in microseconds.
    #[arg(long = "delay-us", default_value_t = DEFAULT_INTER_PACKET_DELAY_US)]
    delay_us: u64,
}

// -----------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------

/// Validated sender configuration.
///
/// Can be built from [`Args`] via [`TryFrom<Args>`], or programmatically
/// via [`ConfigBuilder`] (see [`Config::builder`]).
///
/// Pass this to [`crate::run`] to execute the FIUDP send pipeline.
///
/// # Errors
///
/// Construction fails if `parity_ratio` is > 100.
#[derive(Debug)]
pub struct Config {
    /// Destination IPv4 address of the TRMNL display.
    pub(crate) target_ip: Ipv4Addr,
    /// Seconds until the terminal's next wake window.
    pub(crate) rendezvous_secs: u32,
    /// Path to the 32-byte pre-shared key file.
    pub(crate) key_path: PathBuf,
    /// Where to read the input frame from (file or stdin).
    pub(crate) input: InputSource,
    /// Percentage of parity shards relative to data shards.
    pub(crate) parity_ratio: ParityRatio,
    /// UDP port on the target device.
    pub(crate) target_port: u16,
    /// Delay injected between consecutive UDP sends.
    pub(crate) delay: Duration,
}

impl Config {
    /// Create a [`ConfigBuilder`] for programmatic construction.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::net::Ipv4Addr;
    /// use fiudp_cli::Config;
    ///
    /// let config = Config::builder()
    ///     .target(Ipv4Addr::new(192, 168, 1, 42))
    ///     .wake_at(3600)
    ///     .key_file("./psk.bin")
    ///     .image("./frame.raw")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

impl TryFrom<Args> for Config {
    type Error = FiudpError;

    fn try_from(args: Args) -> Result<Self> {
        let parity_ratio = ParityRatio::try_from(args.parity_ratio)?;
        let input = match args.image {
            Some(path) => InputSource::File(path),
            None => InputSource::Stdin,
        };

        Ok(Self {
            target_ip: args.target,
            rendezvous_secs: args.wake_at,
            key_path: args.key_file,
            input,
            parity_ratio,
            target_port: args.port,
            delay: Duration::from_micros(args.delay_us),
        })
    }
}

// -----------------------------------------------------------------------
// ConfigBuilder
// -----------------------------------------------------------------------

/// Builder for [`Config`] that does not require [`clap`] parsing.
///
/// Use [`Config::builder`] to create an instance.
///
/// # Required fields
///
/// - [`target`](ConfigBuilder::target) — destination IPv4.
/// - [`wake_at`](ConfigBuilder::wake_at) — rendezvous seconds.
/// - [`key_file`](ConfigBuilder::key_file) — path to the 32-byte PSK.
///
/// All other fields have sensible defaults matching the CLI.
#[derive(Debug)]
pub struct ConfigBuilder {
    /// Destination IPv4 (required).
    target_ip: Option<Ipv4Addr>,
    /// Rendezvous timer in seconds (required).
    rendezvous_secs: Option<u32>,
    /// Path to the PSK file (required).
    key_path: Option<PathBuf>,
    /// Optional input image file path.
    image: Option<PathBuf>,
    /// Parity ratio percentage (default 15).
    parity_ratio: u8,
    /// UDP port (default 5050).
    port: u16,
    /// Inter-packet delay in microseconds (default 500).
    delay_us: u64,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self {
            target_ip: None,
            rendezvous_secs: None,
            key_path: None,
            image: None,
            parity_ratio: 15,
            port: DEFAULT_UDP_PORT,
            delay_us: DEFAULT_INTER_PACKET_DELAY_US,
        }
    }
}

impl ConfigBuilder {
    /// Set the destination IPv4 address (**required**).
    pub fn target(mut self, ip: Ipv4Addr) -> Self {
        self.target_ip = Some(ip);
        self
    }

    /// Set the rendezvous timer in seconds (**required**).
    pub fn wake_at(mut self, secs: u32) -> Self {
        self.rendezvous_secs = Some(secs);
        self
    }

    /// Set the path to the 32-byte PSK file (**required**).
    pub fn key_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.key_path = Some(path.into());
        self
    }

    /// Set the input image file path. If omitted, reads from stdin.
    pub fn image(mut self, path: impl Into<PathBuf>) -> Self {
        self.image = Some(path.into());
        self
    }

    /// Set the parity ratio percentage (0–100, default 15).
    pub fn parity_ratio(mut self, percent: u8) -> Self {
        self.parity_ratio = percent;
        self
    }

    /// Set the UDP port (default 5050).
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the inter-packet delay in microseconds (default 500).
    pub fn delay_us(mut self, us: u64) -> Self {
        self.delay_us = us;
        self
    }

    /// Consume the builder and produce a validated [`Config`].
    ///
    /// # Errors
    ///
    /// Returns [`FiudpError::InvalidParityRatio`] if `parity_ratio` > 100.
    ///
    /// # Panics
    ///
    /// Panics if a required field (`target`, `wake_at`, `key_file`) was not set.
    pub fn build(self) -> Result<Config> {
        let parity_ratio = ParityRatio::try_from(self.parity_ratio)?;
        let input = match self.image {
            Some(path) => InputSource::File(path),
            None => InputSource::Stdin,
        };
        Ok(Config {
            target_ip: self.target_ip.expect("ConfigBuilder: target is required"),
            rendezvous_secs: self
                .rendezvous_secs
                .expect("ConfigBuilder: wake_at is required"),
            key_path: self.key_path.expect("ConfigBuilder: key_file is required"),
            input,
            parity_ratio,
            target_port: self.port,
            delay: Duration::from_micros(self.delay_us),
        })
    }
}

// -----------------------------------------------------------------------
// ParityRatio
// -----------------------------------------------------------------------

/// Validated parity ratio percentage (0–100).
///
/// This type guarantees at construction time that the value is within
/// the valid range. A ratio of 0 means no parity shards are generated;
/// a ratio of 100 means one parity shard per data shard.
///
/// The number of parity shards for a given data shard count is computed
/// as `ceil(data_shards × ratio / 100)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ParityRatio(u8);

impl ParityRatio {
    /// Compute the number of parity shards for the given data shard count.
    ///
    /// Uses ceiling division so that even a single data shard with a
    /// non-zero ratio produces at least one parity shard.
    pub(crate) fn parity_shards(self, data_shards: usize) -> usize {
        if self.0 == 0 {
            return 0;
        }

        let numerator = data_shards.saturating_mul(self.0 as usize);
        numerator.div_ceil(100)
    }
}

impl TryFrom<u8> for ParityRatio {
    type Error = FiudpError;

    fn try_from(value: u8) -> Result<Self> {
        if value > 100 {
            return Err(FiudpError::InvalidParityRatio(value));
        }

        Ok(Self(value))
    }
}

// -----------------------------------------------------------------------
// InputSource
// -----------------------------------------------------------------------

/// Where to read the input frame from.
///
/// The FIUDP sender can read from a regular file or from standard input,
/// following the UNIX composability principle (see SPEC.md §1).
#[derive(Debug)]
pub(crate) enum InputSource {
    /// Read the frame from a file at the given path.
    File(PathBuf),
    /// Read the frame from standard input (for pipe-based workflows).
    Stdin,
}

/// Abstraction over frame reading for testability.
///
/// Both [`InputSource::File`] and [`InputSource::Stdin`] implement this
/// trait. Tests can substitute a `Vec<u8>` wrapper.
pub(crate) trait InputReader {
    /// Read the entire input frame into a byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`FiudpError::Io`] if the read fails.
    fn read_all(&self) -> Result<Vec<u8>>;
}

impl InputReader for InputSource {
    fn read_all(&self) -> Result<Vec<u8>> {
        match self {
            InputSource::File(path) => fs::read(path).map_err(|e| FiudpError::Io {
                context: format!("failed to read input file {}", path.display()),
                source: e,
            }),
            InputSource::Stdin => {
                let mut buf = Vec::new();
                io::stdin()
                    .lock()
                    .read_to_end(&mut buf)
                    .map_err(|e| FiudpError::Io {
                        context: "failed to read from stdin".into(),
                        source: e,
                    })?;
                Ok(buf)
            }
        }
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_ratio_validation() {
        assert!(ParityRatio::try_from(0).is_ok());
        assert!(ParityRatio::try_from(100).is_ok());
        assert!(ParityRatio::try_from(101).is_err());
    }

    #[test]
    fn parity_ratio_rounds_up() {
        let ratio = ParityRatio::try_from(15).unwrap();
        assert_eq!(ratio.parity_shards(10), 2);
        assert_eq!(ratio.parity_shards(1), 1);
        assert_eq!(ratio.parity_shards(0), 0);
    }
}
