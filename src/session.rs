//! Persistent, monotonically increasing session ID storage.
//!
//! The FIUDP protocol requires a strictly increasing `session_id` to
//! guarantee AEAD nonce uniqueness and enable replay protection on the
//! receiver side (see SPEC.md §3.1 and §4).
//!
//! [`SessionIdStore`] manages this counter by persisting it alongside
//! the PSK file with a `.session_id` extension. Each call to
//! [`SessionIdStore::next`] atomically reads the current value,
//! increments it, writes back, and returns the new value.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{FiudpError, Result};
use crate::types::SessionId;

/// File-backed monotonic session ID counter.
///
/// The session ID is stored as a 2-byte big-endian `u16` in a file
/// whose path is derived from the PSK key file path by replacing
/// the extension with `.session_id`.
///
/// # Example
///
/// If the key file is `./psk.bin`, the session file is `./psk.session_id`.
///
/// # Overflow
///
/// When the counter reaches `u16::MAX` (65 535), [`next`](Self::next)
/// returns [`FiudpError::SessionIdOverflow`]. At that point the PSK
/// must be rotated and the receiver state reset.
pub(crate) struct SessionIdStore {
    /// Path to the `.session_id` file.
    path: PathBuf,
}

impl SessionIdStore {
    /// Create a store derived from the given key file path.
    ///
    /// The session file path is `key_path` with its extension replaced
    /// by `.session_id`.
    pub(crate) fn new(key_path: &Path) -> Self {
        let mut path = key_path.to_path_buf();
        path.set_extension("session_id");
        Self { path }
    }

    /// Read the current session ID, increment it, persist, and return.
    ///
    /// - If the session file does not exist, starts at 1.
    /// - If the file exists but is malformed, returns [`FiudpError::InvalidSessionFile`].
    /// - If the counter would overflow `u16::MAX`, returns [`FiudpError::SessionIdOverflow`].
    ///
    /// # Errors
    ///
    /// See the individual variants above, plus [`FiudpError::Io`] for
    /// disk read/write failures.
    pub(crate) fn next(&self) -> Result<SessionId> {
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

        let next_raw = match current {
            Some(value) => value.checked_add(1).ok_or(FiudpError::SessionIdOverflow)?,
            None => 1,
        };

        fs::write(&self.path, next_raw.to_be_bytes()).map_err(|e| FiudpError::Io {
            context: format!("failed to write session_id file {}", self.path.display()),
            source: e,
        })?;

        Ok(SessionId::new(next_raw))
    }
}
