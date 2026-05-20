//! # fiudp-cli
//!
//! Unidirectional UDP sender implementing the **FIUDP protocol** for
//! streaming raw image frames to TRMNL-class e-paper displays.
//!
//! ## Overview
//!
//! `fiudp-cli` reads an opaque byte stream (typically a raw BMP frame),
//! applies **Reed-Solomon forward error correction** (FEC), encrypts each
//! shard with **ChaCha20-Poly1305** authenticated encryption, and streams
//! the resulting packets over UDP in a single burst.
//!
//! The protocol is stateless and one-way: no handshake, no acknowledgements,
//! no keep-alive. The only persistent state is a monotonically increasing
//! session identifier stored alongside the pre-shared key file.
//!
//! ## Public API
//!
//! The library exposes these items for integration as a Rust dependency:
//!
//! - [`Args`] — CLI argument struct (derives [`clap::Parser`]).
//! - [`Config`] — Validated configuration built from `Args` via
//!   [`TryFrom<Args>`], or programmatically via [`ConfigBuilder`].
//! - [`ConfigBuilder`] — Builder for [`Config`] without clap parsing.
//! - [`run`] — Executes the full FIUDP send pipeline.
//! - [`FiudpError`] — Typed error enum for all failure modes.
//!
//! ### Quick start (CLI)
//!
//! ```rust,no_run
//! use fiudp_cli::{Args, Config, run};
//! use clap::Parser;
//!
//! let args = Args::parse();
//! let config = Config::try_from(args).expect("invalid arguments");
//! run(config).expect("send failed");
//! ```
//!
//! ### Programmatic construction (no clap)
//!
//! ```rust,no_run
//! use std::net::Ipv4Addr;
//! use fiudp_cli::{Config, run};
//!
//! let config = Config::builder()
//!     .target(Ipv4Addr::new(192, 168, 1, 42))
//!     .wake_at(3600)
//!     .key_file("./psk.bin")
//!     .image("./frame.raw")
//!     .build()
//!     .unwrap();
//!
//! run(config).unwrap();
//! ```
//!
//! ## Wire format
//!
//! Each UDP packet is exactly [`PACKET_SIZE`] (1 428) bytes:
//!
//! | Offset | Size | Field              | Encoding         |
//! |--------|------|--------------------|------------------|
//! | 0      | 2    | `session_id`       | u16 big-endian   |
//! | 2      | 2    | `shard_index`      | u16 big-endian   |
//! | 4      | 2    | `data_shards`      | u16 big-endian   |
//! | 6      | 2    | `parity_shards`    | u16 big-endian   |
//! | 8      | 4    | `rendezvous_secs`  | u32 big-endian   |
//! | 12     | 16   | AEAD tag           | Poly1305         |
//! | 28     | 1400 | shard ciphertext   | ChaCha20         |
//!
//! The nonce is **not** transmitted; it is derived deterministically:
//! `session_id (2) ‖ shard_index (2) ‖ 0x00…00 (8)`.
//!
//! ## Security considerations
//!
//! - Uses a **256-bit pre-shared key** (PSK) for ChaCha20-Poly1305.
//! - Header fields are authenticated as Additional Authenticated Data (AAD);
//!   tampering triggers an authentication failure on the receiver.
//! - **Session IDs are monotonically increasing** to prevent replay attacks.
//!   When `session_id` approaches `u16::MAX`, the PSK must be rotated.
//! - The protocol does **not** hide metadata (IP addresses, timing).
//!
//! ## Feature flags
//!
//! None. The crate has no optional features.
//!
//! For the full protocol specification, see
//! [`SPEC.md`](https://github.com/Thiru-sama/Fin-Amor-s-Ideal-UDP-FIUDP-CLI/blob/main/SPEC.md).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::Parser;
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Typed error enum for all fallible operations in the FIUDP sender.
///
/// Unlike opaque error types, `FiudpError` lets downstream consumers
/// `match` on specific failure modes and handle them programmatically.
///
/// # Example
///
/// ```rust,no_run
/// use fiudp_cli::{Args, Config, run, FiudpError};
/// use clap::Parser;
///
/// let args = Args::parse();
/// let config = Config::try_from(args).unwrap();
/// match run(config) {
///     Ok(()) => println!("sent"),
///     Err(FiudpError::EmptyInput) => eprintln!("nothing to send"),
///     Err(e) => eprintln!("error: {e}"),
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum FiudpError {
    /// Parity ratio exceeds the valid range of 0–100.
    #[error("invalid parity ratio {0}: must be 0–100")]
    InvalidParityRatio(u8),

    /// The key file does not contain exactly 32 bytes.
    #[error("key file must contain exactly 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// The session ID file exists but does not contain exactly 2 bytes.
    #[error("session_id file must contain exactly 2 bytes")]
    InvalidSessionFile,

    /// The monotonic session counter reached `u16::MAX`.
    ///
    /// Rotate the PSK and reset the receiver before continuing.
    #[error("session_id overflow (u16::MAX reached); rotate PSK and reset receiver state")]
    SessionIdOverflow,

    /// The input frame is empty (zero bytes).
    #[error("input is empty")]
    EmptyInput,

    /// The total number of shards (data + parity) exceeds `u16::MAX`.
    #[error("total shards {0} exceeds u16 limit")]
    TooManyShards(usize),

    /// A shard payload has an unexpected size (internal invariant violation).
    #[error("invalid shard size {actual}, expected {expected}")]
    InvalidShardSize {
        /// Actual size received.
        actual: usize,
        /// Expected [`SHARD_SIZE`].
        expected: usize,
    },

    /// A UDP send wrote fewer bytes than the full packet.
    #[error("short UDP send: {sent} of {expected} bytes")]
    ShortSend {
        /// Bytes actually sent.
        sent: usize,
        /// Bytes expected to send.
        expected: usize,
    },

    /// ChaCha20-Poly1305 encryption failed.
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Reed-Solomon FEC encoding failed.
    #[error("FEC encoding failed: {0}")]
    Fec(String),

    /// An I/O operation failed, with context describing which operation.
    #[error("{context}")]
    Io {
        /// Human-readable description of the failed operation.
        context: String,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, FiudpError>;

/// Fixed shard payload size in bytes (1 400).
///
/// Each shard — whether data or parity — occupies exactly this many bytes
/// in the packet payload. Input frames are zero-padded to a multiple of
/// this value before FEC encoding.
pub const SHARD_SIZE: usize = 1400;

/// AEAD nonce length in bytes (12, per the ChaCha20-Poly1305 spec).
pub const NONCE_SIZE: usize = 12;

/// AEAD authentication tag length in bytes (16, Poly1305).
pub const TAG_SIZE: usize = 16;

/// Size of the `rendezvous_secs` header field in bytes.
pub const RENDEZVOUS_SIZE: usize = 4;

/// Size of the `session_id` header field in bytes.
pub const SESSION_ID_SIZE: usize = 2;

/// Size of the `shard_index` header field in bytes.
pub const SHARD_INDEX_SIZE: usize = 2;

/// Size of the `data_shards` header field in bytes.
pub const DATA_SHARDS_SIZE: usize = 2;

/// Size of the `parity_shards` header field in bytes.
pub const PARITY_SHARDS_SIZE: usize = 2;

/// Total size of the AAD (Additional Authenticated Data) region in bytes.
///
/// This is the concatenation of `session_id`, `shard_index`, `data_shards`,
/// `parity_shards`, and `rendezvous_secs` — 12 bytes total.
pub const AAD_SIZE: usize =
    SESSION_ID_SIZE + SHARD_INDEX_SIZE + DATA_SHARDS_SIZE + PARITY_SHARDS_SIZE + RENDEZVOUS_SIZE;

/// Total header size in bytes (AAD + AEAD tag = 28).
pub const HEADER_SIZE: usize = AAD_SIZE + TAG_SIZE;

/// Total UDP packet size in bytes (header + shard payload = 1 428).
pub const PACKET_SIZE: usize = HEADER_SIZE + SHARD_SIZE;

/// Byte offset of `session_id` within the packet header.
pub const SESSION_ID_OFFSET: usize = 0;

/// Byte offset of `shard_index` within the packet header.
pub const SHARD_INDEX_OFFSET: usize = SESSION_ID_OFFSET + SESSION_ID_SIZE;

/// Byte offset of `data_shards` within the packet header.
pub const DATA_SHARDS_OFFSET: usize = SHARD_INDEX_OFFSET + SHARD_INDEX_SIZE;

/// Byte offset of `parity_shards` within the packet header.
pub const PARITY_SHARDS_OFFSET: usize = DATA_SHARDS_OFFSET + DATA_SHARDS_SIZE;

/// Byte offset of `rendezvous_secs` within the packet header.
pub const RENDEZVOUS_OFFSET: usize = PARITY_SHARDS_OFFSET + PARITY_SHARDS_SIZE;

/// Byte offset of the AEAD authentication tag within the packet header.
pub const TAG_OFFSET: usize = RENDEZVOUS_OFFSET + RENDEZVOUS_SIZE;

/// Byte offset of the encrypted shard payload within the packet.
pub const PAYLOAD_OFFSET: usize = TAG_OFFSET + TAG_SIZE;

const DEFAULT_UDP_PORT: u16 = 5050;
const DEFAULT_INTER_PACKET_DELAY_US: u64 = 500;



/// Command-line arguments for the FIUDP sender.
///
/// This struct derives [`clap::Parser`] and maps directly to the CLI flags
/// documented in the project README. Use [`Config::try_from`] to validate
/// and convert these arguments into a [`Config`] suitable for [`run`].
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
    /// Target IPv4 address of the TRMNL display
    #[arg(short = 't', long = "target", alias = "ip", value_name = "IP")]
    target: Ipv4Addr,

    /// Wake-up timer in seconds for the next sync cycle
    #[arg(
        short = 'w',
        long = "wake-at",
        alias = "rendezvous",
        value_name = "SECS"
    )]
    wake_at: u32,

    /// Path to the 256-bit (32 bytes) pre-shared key file
    #[arg(short = 'k', long = "key-file", value_name = "FILE")]
    key_file: PathBuf,

    /// Path to the raw input buffer file (fallback to STDIN if omitted)
    #[arg(short = 'i', long = "image", alias = "input", value_name = "FILE")]
    image: Option<PathBuf>,

    /// Percentage of parity shards to generate
    #[arg(
        short = 'p',
        long = "parity-ratio",
        default_value_t = 15,
        value_name = "PERCENT"
    )]
    parity_ratio: u8,

    /// UDP port of the TRMNL receiver
    #[arg(long, default_value_t = DEFAULT_UDP_PORT)]
    port: u16,

    /// Delay between packets in microseconds
    #[arg(long = "delay-us", default_value_t = DEFAULT_INTER_PACKET_DELAY_US)]
    delay_us: u64,
}

/// Validated sender configuration.
///
/// Can be built from [`Args`] via [`TryFrom<Args>`], or programmatically
/// via [`ConfigBuilder`] (see [`Config::builder`]).
///
/// Pass this to [`run`] to execute the FIUDP send pipeline.
///
/// # Errors
///
/// Construction fails if `parity_ratio` is > 100.
#[derive(Debug)]
pub struct Config {
    /// Destination IPv4 address of the TRMNL display.
    target_ip: Ipv4Addr,
    /// Seconds until the terminal's next wake window.
    rendezvous_secs: u32,
    /// Path to the 32-byte pre-shared key file.
    key_path: PathBuf,
    /// Where to read the input frame from (file or stdin).
    input: InputSource,
    /// Percentage of parity shards relative to data shards.
    parity_ratio: ParityRatio,
    /// UDP port on the target device.
    target_port: u16,
    /// Delay injected between consecutive UDP sends.
    delay: Duration,
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
    target_ip: Option<Ipv4Addr>,
    rendezvous_secs: Option<u32>,
    key_path: Option<PathBuf>,
    image: Option<PathBuf>,
    parity_ratio: u8,
    port: u16,
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
    pub fn target(mut self, ip: Ipv4Addr) -> Self { self.target_ip = Some(ip); self }
    /// Set the rendezvous timer in seconds (**required**).
    pub fn wake_at(mut self, secs: u32) -> Self { self.rendezvous_secs = Some(secs); self }
    /// Set the path to the 32-byte PSK file (**required**).
    pub fn key_file(mut self, path: impl Into<PathBuf>) -> Self { self.key_path = Some(path.into()); self }
    /// Set the input image file path. If omitted, reads from stdin.
    pub fn image(mut self, path: impl Into<PathBuf>) -> Self { self.image = Some(path.into()); self }
    /// Set the parity ratio percentage (0–100, default 15).
    pub fn parity_ratio(mut self, percent: u8) -> Self { self.parity_ratio = percent; self }
    /// Set the UDP port (default 5050).
    pub fn port(mut self, port: u16) -> Self { self.port = port; self }
    /// Set the inter-packet delay in microseconds (default 500).
    pub fn delay_us(mut self, us: u64) -> Self { self.delay_us = us; self }

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
            rendezvous_secs: self.rendezvous_secs.expect("ConfigBuilder: wake_at is required"),
            key_path: self.key_path.expect("ConfigBuilder: key_file is required"),
            input,
            parity_ratio,
            target_port: self.port,
            delay: Duration::from_micros(self.delay_us),
        })
    }
}

/// Execute the full FIUDP send pipeline.
///
/// This is the primary entry point for the library. Given a validated
/// [`Config`], it will:
///
/// 1. Read the input frame (from file or stdin).
/// 2. Load the 256-bit pre-shared key and advance the session counter.
/// 3. Pad the frame to a multiple of [`SHARD_SIZE`] bytes.
/// 4. Compute Reed-Solomon parity shards.
/// 5. Encrypt each shard in-place with ChaCha20-Poly1305.
/// 6. Send all packets over UDP with the configured inter-packet delay.
///
/// # Errors
///
/// Returns an error if:
/// - The key file cannot be read or is not exactly 32 bytes.
/// - The input source is empty or unreadable.
/// - The session ID counter overflows `u16::MAX` (rotate the PSK).
/// - A UDP send fails.
///
/// # Example
///
/// ```rust,no_run
/// use fiudp_cli::{Args, Config, run};
/// use clap::Parser;
///
/// let args = Args::parse();
/// let config = Config::try_from(args).unwrap();
/// run(config).unwrap();
/// ```
pub fn run(config: Config) -> Result<()> {
    let reader = config.input;
    let key_path = config.key_path.clone();
    let key_source = FileKeySource::new(config.key_path);
    let key = key_source.load_key()?;
    let session_id = SessionIdStore::new(&key_path).next()?;

    let encryptor = ChaChaEncryptor::new(key);
    let fec = ReedSolomonEngine;
    let sender = UdpPacketSender::new(config.target_ip, config.target_port)?;

    let pipeline = FiudpSender::new(reader, fec, encryptor, sender, config.delay);

    pipeline.send(config.parity_ratio, config.rendezvous_secs, session_id)
}

#[derive(Clone, Copy, Debug)]
struct ParityRatio(u8);

impl ParityRatio {
    fn parity_shards(self, data_shards: usize) -> usize {
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

#[derive(Debug)]
enum InputSource {
    File(PathBuf),
    Stdin,
}

trait InputReader {
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

trait KeySource {
    fn load_key(&self) -> Result<[u8; 32]>;
}

struct FileKeySource {
    path: PathBuf,
}

impl FileKeySource {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl KeySource for FileKeySource {
    fn load_key(&self) -> Result<[u8; 32]> {
        read_key(&self.path)
    }
}

struct SessionIdStore {
    path: PathBuf,
}

impl SessionIdStore {
    fn new(key_path: &Path) -> Self {
        let mut path = key_path.to_path_buf();
        path.set_extension("session_id");
        Self { path }
    }

    fn next(&self) -> Result<u16> {
        let current = match fs::read(&self.path) {
            Ok(bytes) => {
                if bytes.len() != 2 {
                    return Err(FiudpError::InvalidSessionFile);
                }
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&bytes);
                Some(u16::from_be_bytes(buf))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(FiudpError::Io {
                    context: format!("failed to read session_id file {}", self.path.display()),
                    source: err,
                })
            }
        };

        let next = match current {
            Some(value) => value.checked_add(1).ok_or(FiudpError::SessionIdOverflow)?,
            None => 1,
        };

        fs::write(&self.path, next.to_be_bytes()).map_err(|e| FiudpError::Io {
            context: format!("failed to write session_id file {}", self.path.display()),
            source: e,
        })?;

        Ok(next)
    }
}

trait FecEngine {
    fn encode(
        &self,
        data_shards: usize,
        parity_shards: usize,
        shards: &mut [&mut [u8]],
    ) -> Result<()>;
}

struct ReedSolomonEngine;

impl FecEngine for ReedSolomonEngine {
    fn encode(
        &self,
        data_shards: usize,
        parity_shards: usize,
        shards: &mut [&mut [u8]],
    ) -> Result<()> {
        let rse = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| FiudpError::Fec(format!("failed to initialize Reed-Solomon encoder: {e}")))?;
        rse.encode(shards)
            .map_err(|e| FiudpError::Fec(format!("failed to generate parity shards: {e}")))?;
        Ok(())
    }
}

trait Encryptor {
    fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_SIZE]>;
}

struct ChaChaEncryptor {
    cipher: ChaCha20Poly1305,
}

impl ChaChaEncryptor {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
        }
    }
}

impl Encryptor for ChaChaEncryptor {
    fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_SIZE]> {
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer)
            .map_err(|err| FiudpError::Encryption(format!("{err:?}")))?;

        let mut tag_bytes = [0u8; TAG_SIZE];
        tag_bytes.copy_from_slice(tag.as_slice());
        Ok(tag_bytes)
    }
}

struct PacketBuilder {
    session_id: u16,
    rendezvous_secs: u32,
    data_shards: u16,
    parity_shards: u16,
}

impl PacketBuilder {
    fn new(session_id: u16, rendezvous_secs: u32, data_shards: u16, parity_shards: u16) -> Self {
        Self {
            session_id,
            rendezvous_secs,
            data_shards,
            parity_shards,
        }
    }

    fn build_aad(&self, shard_index: u16) -> [u8; AAD_SIZE] {
        let mut aad = [0u8; AAD_SIZE];
        aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_SIZE]
            .copy_from_slice(&self.session_id.to_be_bytes());
        aad[SHARD_INDEX_OFFSET..SHARD_INDEX_OFFSET + SHARD_INDEX_SIZE]
            .copy_from_slice(&shard_index.to_be_bytes());
        aad[DATA_SHARDS_OFFSET..DATA_SHARDS_OFFSET + DATA_SHARDS_SIZE]
            .copy_from_slice(&self.data_shards.to_be_bytes());
        aad[PARITY_SHARDS_OFFSET..PARITY_SHARDS_OFFSET + PARITY_SHARDS_SIZE]
            .copy_from_slice(&self.parity_shards.to_be_bytes());
        aad[RENDEZVOUS_OFFSET..RENDEZVOUS_OFFSET + RENDEZVOUS_SIZE]
            .copy_from_slice(&self.rendezvous_secs.to_be_bytes());
        aad
    }

    fn write_packet(
        &self,
        out: &mut [u8; PACKET_SIZE],
        aad: &[u8; AAD_SIZE],
        tag: &[u8; TAG_SIZE],
        payload: &[u8],
    ) -> Result<()> {
        if payload.len() != SHARD_SIZE {
            return Err(FiudpError::InvalidShardSize {
                actual: payload.len(),
                expected: SHARD_SIZE,
            });
        }

        out[..AAD_SIZE].copy_from_slice(aad);
        out[TAG_OFFSET..TAG_OFFSET + TAG_SIZE].copy_from_slice(tag);
        out[PAYLOAD_OFFSET..PAYLOAD_OFFSET + SHARD_SIZE].copy_from_slice(payload);

        Ok(())
    }
}

trait PacketSender {
    fn send(&self, packet: &[u8]) -> Result<()>;
}

struct UdpPacketSender {
    socket: UdpSocket,
    target: SocketAddrV4,
}

impl UdpPacketSender {
    fn new(target_ip: Ipv4Addr, port: u16) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| FiudpError::Io {
            context: "failed to bind UDP socket".into(),
            source: e,
        })?;
        let target = SocketAddrV4::new(target_ip, port);
        socket.connect(target).map_err(|e| FiudpError::Io {
            context: format!("failed to connect UDP socket to {}", target),
            source: e,
        })?;

        Ok(Self { socket, target })
    }
}

impl PacketSender for UdpPacketSender {
    fn send(&self, packet: &[u8]) -> Result<()> {
        let sent = self
            .socket
            .send(packet)
            .map_err(|e| FiudpError::Io {
                context: format!("failed to send UDP packet to {}", self.target),
                source: e,
            })?;
        if sent != packet.len() {
            return Err(FiudpError::ShortSend {
                sent,
                expected: packet.len(),
            });
        }

        Ok(())
    }
}

struct FiudpSender<R, F, E, S> {
    reader: R,
    fec: F,
    encryptor: E,
    sender: S,
    delay: Duration,
}

impl<R, F, E, S> FiudpSender<R, F, E, S>
where
    R: InputReader,
    F: FecEngine,
    E: Encryptor,
    S: PacketSender,
{
    fn new(reader: R, fec: F, encryptor: E, sender: S, delay: Duration) -> Self {
        Self {
            reader,
            fec,
            encryptor,
            sender,
            delay,
        }
    }

    fn send(&self, parity_ratio: ParityRatio, rendezvous_secs: u32, session_id: u16) -> Result<()> {
        let mut payload = self.reader.read_all()?;
        if payload.is_empty() {
            return Err(FiudpError::EmptyInput);
        }

        pad_to_shard_size(&mut payload);

        let data_shards = payload.len() / SHARD_SIZE;
        if data_shards == 0 {
            return Err(FiudpError::EmptyInput);
        }

        let parity_shards = parity_ratio.parity_shards(data_shards);
        let total_shards = data_shards + parity_shards;

        if total_shards > u16::MAX as usize {
            return Err(FiudpError::TooManyShards(total_shards));
        }

        // Safe: guarded by the check above.
        let data_shards_u16 = data_shards as u16;
        let parity_shards_u16 = parity_shards as u16;

        let mut parity_buffers = Vec::with_capacity(parity_shards);
        for _ in 0..parity_shards {
            parity_buffers.push(vec![0u8; SHARD_SIZE]);
        }

        let mut shards: Vec<&mut [u8]> = payload.chunks_exact_mut(SHARD_SIZE).collect();
        for parity in parity_buffers.iter_mut() {
            shards.push(parity.as_mut_slice());
        }

        if parity_shards > 0 {
            self.fec.encode(data_shards, parity_shards, &mut shards)?;
        }

        let packet_builder = PacketBuilder::new(
            session_id,
            rendezvous_secs,
            data_shards_u16,
            parity_shards_u16,
        );
        let mut packet = [0u8; PACKET_SIZE];

        let shard_count = shards.len();
        for (index, shard_ref) in shards.iter_mut().enumerate() {
            let shard = &mut **shard_ref;
            debug_assert_eq!(shard.len(), SHARD_SIZE);

            let nonce = derive_nonce(session_id, index as u16);

            let aad = packet_builder.build_aad(index as u16);
            let tag = self.encryptor.encrypt_in_place(&nonce, &aad, shard)?;

            packet_builder.write_packet(&mut packet, &aad, &tag, shard)?;
            self.sender.send(&packet)?;

            if index + 1 < shard_count {
                thread::sleep(self.delay);
            }
        }

        Ok(())
    }
}

fn pad_to_shard_size(buf: &mut Vec<u8>) {
    let rem = buf.len() % SHARD_SIZE;
    if rem == 0 {
        return;
    }

    let new_len = buf.len() + (SHARD_SIZE - rem);
    buf.resize(new_len, 0u8);
}

fn derive_nonce(session_id: u16, shard_index: u16) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..2].copy_from_slice(&session_id.to_be_bytes());
    nonce[2..4].copy_from_slice(&shard_index.to_be_bytes());
    nonce
}

fn read_key(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).map_err(|e| FiudpError::Io {
        context: format!("failed to read key file {}", path.display()),
        source: e,
    })?;
    if bytes.len() != 32 {
        return Err(FiudpError::InvalidKeyLength(bytes.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_to_shard_size_extends_with_zeroes() {
        let mut buf = vec![0xAB; SHARD_SIZE + 1];
        pad_to_shard_size(&mut buf);

        assert_eq!(buf.len(), SHARD_SIZE * 2);
        assert!(buf[..SHARD_SIZE + 1].iter().all(|b| *b == 0xAB));
        assert!(buf[SHARD_SIZE + 1..].iter().all(|b| *b == 0));
    }

    #[test]
    fn pad_to_shard_size_noop_on_exact_multiple() {
        let mut buf = vec![0xCD; SHARD_SIZE * 2];
        pad_to_shard_size(&mut buf);

        assert_eq!(buf.len(), SHARD_SIZE * 2);
        assert!(buf.iter().all(|b| *b == 0xCD));
    }

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

    #[test]
    fn packet_builder_writes_header_and_payload() {
        let builder = PacketBuilder::new(0xABCD, 0x01020304, 0x0020, 0x0004);
        let mut packet = [0u8; PACKET_SIZE];
        let tag = [0x22; TAG_SIZE];
        let payload = vec![0x33; SHARD_SIZE];
        let aad = builder.build_aad(0x1234);

        builder
            .write_packet(&mut packet, &aad, &tag, &payload)
            .unwrap();

        assert_eq!(
            &packet[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_SIZE],
            &0xABCDu16.to_be_bytes()
        );
        assert_eq!(
            &packet[SHARD_INDEX_OFFSET..SHARD_INDEX_OFFSET + SHARD_INDEX_SIZE],
            &0x1234u16.to_be_bytes()
        );
        assert_eq!(
            &packet[DATA_SHARDS_OFFSET..DATA_SHARDS_OFFSET + DATA_SHARDS_SIZE],
            &0x0020u16.to_be_bytes()
        );
        assert_eq!(
            &packet[PARITY_SHARDS_OFFSET..PARITY_SHARDS_OFFSET + PARITY_SHARDS_SIZE],
            &0x0004u16.to_be_bytes()
        );
        assert_eq!(
            &packet[RENDEZVOUS_OFFSET..RENDEZVOUS_OFFSET + RENDEZVOUS_SIZE],
            &0x01020304u32.to_be_bytes()
        );
        assert_eq!(&packet[TAG_OFFSET..TAG_OFFSET + TAG_SIZE], &tag);
        assert_eq!(
            &packet[PAYLOAD_OFFSET..PAYLOAD_OFFSET + SHARD_SIZE],
            payload.as_slice()
        );
    }

    #[test]
    fn packet_builder_rejects_wrong_payload_size() {
        let builder = PacketBuilder::new(0xABCD, 0, 1, 0);
        let mut packet = [0u8; PACKET_SIZE];
        let tag = [0u8; TAG_SIZE];
        let payload = vec![0u8; SHARD_SIZE - 1];
        let aad = builder.build_aad(1);

        assert!(builder
            .write_packet(&mut packet, &aad, &tag, &payload)
            .is_err());
    }
}
