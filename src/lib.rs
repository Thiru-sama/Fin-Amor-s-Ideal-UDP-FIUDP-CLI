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
//! ### Type-safe wire-format types
//!
//! The following newtypes provide compile-time safety for protocol
//! fields that would otherwise be interchangeable primitives:
//!
//! - [`SessionId`] — monotonic session identifier (`u16`).
//! - [`ShardIndex`] — zero-based shard index (`u16`).
//! - [`DataShardCount`] — number of data shards (`u16`).
//! - [`ParityShardCount`] — number of parity shards (`u16`).
//! - [`RendezvousSecs`] — advisory wake-up timer (`u32`).
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
//! ## Module organisation
//!
//! | Module       | Responsibility                                        |
//! |--------------|-------------------------------------------------------|
//! | `config`     | CLI arguments, validated configuration, builder        |
//! | `crypto`     | AEAD encryption, nonce derivation, key loading         |
//! | [`error`]    | `FiudpError` enum and `Result` alias                  |
//! | `fec`        | Reed-Solomon forward error correction                  |
//! | [`protocol`] | Wire-format constants, packet assembly, frame padding  |
//! | `sender`     | UDP transport and transmission pipeline orchestration  |
//! | `session`    | Persistent monotonic session ID counter                |
//! | [`types`]    | Semantic newtypes for wire-format fields               |
//!
//! ## Feature flags
//!
//! None. The crate has no optional features.
//!
//! For the full protocol specification, see
//! [`SPEC.md`](https://github.com/Thiru-sama/Fin-Amor-s-Ideal-UDP-FIUDP-CLI/blob/main/SPEC.md).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// -----------------------------------------------------------------------
// Module declarations
// -----------------------------------------------------------------------

mod config;
mod crypto;
pub mod error;
mod fec;
pub mod protocol;
mod sender;
mod session;
pub mod types;

// -----------------------------------------------------------------------
// Public re-exports
// -----------------------------------------------------------------------

pub use config::{Args, Config, ConfigBuilder};
pub use error::{FiudpError, Result};
pub use protocol::{
    AAD_SIZE, DATA_SHARDS_OFFSET, DATA_SHARDS_SIZE, HEADER_SIZE, NONCE_SIZE, PACKET_SIZE,
    PARITY_SHARDS_OFFSET, PARITY_SHARDS_SIZE, PAYLOAD_OFFSET, RENDEZVOUS_OFFSET, RENDEZVOUS_SIZE,
    SESSION_ID_OFFSET, SESSION_ID_SIZE, SHARD_INDEX_OFFSET, SHARD_INDEX_SIZE, SHARD_SIZE,
    TAG_OFFSET, TAG_SIZE,
};
pub use types::{DataShardCount, ParityShardCount, RendezvousSecs, SessionId, ShardIndex};

// -----------------------------------------------------------------------
// Crate-internal imports for run()
// -----------------------------------------------------------------------

use crypto::{ChaChaEncryptor, FileKeySource, KeySource};
use fec::ReedSolomonEngine;
use sender::{FiudpSender, UdpPacketSender};
use session::SessionIdStore;

// -----------------------------------------------------------------------
// Public entry point
// -----------------------------------------------------------------------

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

    pipeline.send(
        config.parity_ratio,
        RendezvousSecs::new(config.rendezvous_secs),
        session_id,
    )
}
