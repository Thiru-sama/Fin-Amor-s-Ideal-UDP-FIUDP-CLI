//! Cryptographic operations for the FIUDP sender.
//!
//! This module provides the [`Encryptor`] trait (abstracting AEAD
//! encryption for testability), its production implementation
//! [`ChaChaEncryptor`] using ChaCha20-Poly1305, the deterministic
//! [`derive_nonce`] function, and the key-loading helpers.
//!
//! ## Nonce derivation
//!
//! The AEAD nonce is **never** transmitted on the wire. Instead, both
//! sender and receiver derive it identically from `session_id` and
//! `shard_index`:
//!
//! ```text
//! ┌───────────┬─────────────┬────────────────────────┐
//! │ session_id│ shard_index │  0x00 … 00  (8 bytes)  │
//! │  (2 BE)   │   (2 BE)    │                        │
//! └───────────┴─────────────┴────────────────────────┘
//!            12 bytes total (NONCE_SIZE)
//! ```
//!
//! Nonce uniqueness is guaranteed as long as `session_id` is strictly
//! monotonic under the same PSK (see SPEC.md §4).

use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::{FiudpError, Result};
use crate::protocol::{NONCE_SIZE, TAG_SIZE};
use crate::types::{SessionId, ShardIndex};

// -----------------------------------------------------------------------
// Encryptor trait
// -----------------------------------------------------------------------

/// Abstraction over AEAD encryption for the FIUDP sender.
///
/// The trait exists primarily for testability: in unit tests, a mock
/// encryptor can be substituted to verify the pipeline without pulling
/// in the real ChaCha20-Poly1305 implementation.
pub(crate) trait Encryptor {
    /// Encrypt `buffer` in-place and return the authentication tag.
    ///
    /// # Parameters
    ///
    /// - `nonce`: 12-byte nonce derived from session ID and shard index.
    /// - `aad`: Additional Authenticated Data (the 12-byte packet header).
    /// - `buffer`: Plaintext shard payload; encrypted in-place on return.
    ///
    /// # Errors
    ///
    /// Returns [`FiudpError::Encryption`] if the AEAD operation fails.
    fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_SIZE]>;
}

// -----------------------------------------------------------------------
// ChaChaEncryptor
// -----------------------------------------------------------------------

/// Production [`Encryptor`] backed by ChaCha20-Poly1305.
///
/// Wraps a [`ChaCha20Poly1305`] cipher instance initialised with
/// the 256-bit PSK.
pub(crate) struct ChaChaEncryptor {
    /// The initialised AEAD cipher.
    cipher: ChaCha20Poly1305,
}

impl ChaChaEncryptor {
    /// Create a new encryptor from a 32-byte pre-shared key.
    pub(crate) fn new(key: [u8; 32]) -> Self {
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

// -----------------------------------------------------------------------
// Nonce derivation
// -----------------------------------------------------------------------

/// Derive the 12-byte AEAD nonce for a given session and shard.
///
/// Layout: `session_id (2 BE) ‖ shard_index (2 BE) ‖ 0x00…00 (8)`.
///
/// This deterministic derivation means the nonce is **not** transmitted
/// on the wire — both endpoints compute it independently.
///
/// # Security
///
/// Nonce uniqueness relies on `session_id` being strictly monotonic
/// under a given PSK. If `session_id` wraps around (`u16::MAX`), the
/// PSK **must** be rotated before any further transmissions.
pub(crate) fn derive_nonce(session_id: SessionId, shard_index: ShardIndex) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..2].copy_from_slice(&session_id.to_be_bytes());
    nonce[2..4].copy_from_slice(&shard_index.to_be_bytes());
    nonce
}

// -----------------------------------------------------------------------
// Key loading
// -----------------------------------------------------------------------

/// Trait abstracting key loading for testability.
///
/// The production implementation ([`FileKeySource`]) reads from disk;
/// tests can provide an in-memory key.
pub(crate) trait KeySource {
    /// Load and return the 256-bit pre-shared key.
    ///
    /// # Errors
    ///
    /// Returns [`FiudpError::Io`] if the key file cannot be read, or
    /// [`FiudpError::InvalidKeyLength`] if it is not exactly 32 bytes.
    fn load_key(&self) -> Result<[u8; 32]>;
}

/// Loads a 32-byte PSK from a file on disk.
///
/// The file is expected to contain exactly 32 raw bytes (not hex, not
/// base64). Generate a key with:
///
/// ```sh
/// dd if=/dev/urandom of=psk.bin bs=32 count=1
/// ```
pub(crate) struct FileKeySource {
    /// Path to the raw 32-byte key file.
    path: PathBuf,
}

impl FileKeySource {
    /// Create a new key source pointing to the given path.
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl KeySource for FileKeySource {
    fn load_key(&self) -> Result<[u8; 32]> {
        read_key(&self.path)
    }
}

/// Read a 32-byte PSK from the given file path.
///
/// # Errors
///
/// - [`FiudpError::Io`] if the file cannot be read.
/// - [`FiudpError::InvalidKeyLength`] if the file is not exactly 32 bytes.
pub(crate) fn read_key(path: &Path) -> Result<[u8; 32]> {
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
