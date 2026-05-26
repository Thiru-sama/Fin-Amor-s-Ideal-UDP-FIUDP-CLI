//! FIUDP wire-format constants, packet construction, and frame padding.
//!
//! This module contains every constant that describes the on-wire layout
//! of a FIUDP packet (sizes, offsets), the `PacketBuilder` that
//! assembles header + tag + payload into a fixed-size buffer, and the
//! `pad_to_shard_size` helper that zero-extends a frame to a multiple
//! of [`SHARD_SIZE`].
//!
//! All constants reference **SPEC.md §3.4** unless noted otherwise.

use crate::error::{FiudpError, Result};
use crate::types::{DataShardCount, ParityShardCount, RendezvousSecs, SessionId, ShardIndex};

// -----------------------------------------------------------------------
// Size constants
// -----------------------------------------------------------------------

/// Fixed shard payload size in bytes (1 400).
///
/// Each shard — whether data or parity — occupies exactly this many bytes
/// in the packet payload. Input frames are zero-padded to a multiple of
/// this value before FEC encoding.
///
/// Chosen to stay well below the typical Ethernet MTU of 1 500 once
/// the 28-byte header is added.
pub const SHARD_SIZE: usize = 1400;

/// AEAD nonce length in bytes (12, per the ChaCha20-Poly1305 spec).
///
/// The nonce is **not** transmitted on the wire; it is derived
/// deterministically from `session_id` and `shard_index`.
/// See `crypto::derive_nonce`.
pub const NONCE_SIZE: usize = 12;

/// AEAD authentication tag length in bytes (16, Poly1305).
///
/// The tag authenticates the encrypted shard payload together with the
/// AAD header fields. It is placed at offset 12 in the packet.
pub const TAG_SIZE: usize = 16;

/// Size of the `rendezvous_secs` header field in bytes (4).
pub const RENDEZVOUS_SIZE: usize = 4;

/// Size of the `session_id` header field in bytes (2).
pub const SESSION_ID_SIZE: usize = 2;

/// Size of the `shard_index` header field in bytes (2).
pub const SHARD_INDEX_SIZE: usize = 2;

/// Size of the `data_shards` header field in bytes (2).
pub const DATA_SHARDS_SIZE: usize = 2;

/// Size of the `parity_shards` header field in bytes (2).
pub const PARITY_SHARDS_SIZE: usize = 2;

/// Total size of the AAD (Additional Authenticated Data) region in bytes.
///
/// This is the concatenation of the five header fields:
/// `session_id` (2) + `shard_index` (2) + `data_shards` (2)
/// + `parity_shards` (2) + `rendezvous_secs` (4) = **12 bytes**.
///
/// The receiver MUST authenticate these fields before processing a shard.
pub const AAD_SIZE: usize =
    SESSION_ID_SIZE + SHARD_INDEX_SIZE + DATA_SHARDS_SIZE + PARITY_SHARDS_SIZE + RENDEZVOUS_SIZE;

/// Total header size in bytes (AAD + AEAD tag = 28).
///
/// ```text
/// ┌────────────────────── 28 bytes ──────────────────────┐
/// │  AAD (12 bytes)  │  Poly1305 tag (16 bytes)          │
/// └──────────────────┴───────────────────────────────────┘
/// ```
pub const HEADER_SIZE: usize = AAD_SIZE + TAG_SIZE;

/// Total UDP packet size in bytes (header + shard payload = 1 428).
///
/// Every FIUDP packet is exactly this size, with no length variability.
pub const PACKET_SIZE: usize = HEADER_SIZE + SHARD_SIZE;

// -----------------------------------------------------------------------
// Offset constants
// -----------------------------------------------------------------------

/// Byte offset of `session_id` within the packet header (0).
pub const SESSION_ID_OFFSET: usize = 0;

/// Byte offset of `shard_index` within the packet header (2).
pub const SHARD_INDEX_OFFSET: usize = SESSION_ID_OFFSET + SESSION_ID_SIZE;

/// Byte offset of `data_shards` within the packet header (4).
pub const DATA_SHARDS_OFFSET: usize = SHARD_INDEX_OFFSET + SHARD_INDEX_SIZE;

/// Byte offset of `parity_shards` within the packet header (6).
pub const PARITY_SHARDS_OFFSET: usize = DATA_SHARDS_OFFSET + DATA_SHARDS_SIZE;

/// Byte offset of `rendezvous_secs` within the packet header (8).
pub const RENDEZVOUS_OFFSET: usize = PARITY_SHARDS_OFFSET + PARITY_SHARDS_SIZE;

/// Byte offset of the AEAD authentication tag within the packet header (12).
pub const TAG_OFFSET: usize = RENDEZVOUS_OFFSET + RENDEZVOUS_SIZE;

/// Byte offset of the encrypted shard payload within the packet (28).
pub const PAYLOAD_OFFSET: usize = TAG_OFFSET + TAG_SIZE;

// -----------------------------------------------------------------------
// PacketBuilder
// -----------------------------------------------------------------------

/// Assembles FIUDP packet headers from session metadata.
///
/// A `PacketBuilder` is created once per session with the immutable
/// session-level fields (`session_id`, `rendezvous_secs`, `data_shards`,
/// `parity_shards`). For each shard, it produces the AAD bytes and
/// writes the complete packet (header + tag + payload) into a
/// caller-supplied `[u8; PACKET_SIZE]` buffer.
///
/// # Wire layout produced
///
/// ```text
/// offset 0   session_id        (2 bytes, BE)
/// offset 2   shard_index       (2 bytes, BE)  ← varies per shard
/// offset 4   data_shards       (2 bytes, BE)
/// offset 6   parity_shards     (2 bytes, BE)
/// offset 8   rendezvous_secs   (4 bytes, BE)
/// offset 12  AEAD tag          (16 bytes)
/// offset 28  shard ciphertext  (1400 bytes)
/// ```
pub(crate) struct PacketBuilder {
    /// Monotonic session identifier for this transmission burst.
    session_id: SessionId,
    /// Advisory wake-up timer for the receiver.
    rendezvous_secs: RendezvousSecs,
    /// Number of data shards in this session.
    data_shards: DataShardCount,
    /// Number of parity shards in this session.
    parity_shards: ParityShardCount,
}

impl PacketBuilder {
    /// Create a new builder for one session.
    ///
    /// All four fields are fixed for the lifetime of the session;
    /// only `shard_index` varies across packets.
    pub(crate) fn new(
        session_id: SessionId,
        rendezvous_secs: RendezvousSecs,
        data_shards: DataShardCount,
        parity_shards: ParityShardCount,
    ) -> Self {
        Self {
            session_id,
            rendezvous_secs,
            data_shards,
            parity_shards,
        }
    }

    /// Build the 12-byte AAD for a given shard index.
    ///
    /// The AAD is the concatenation of all five header fields in wire
    /// order. Both sender and receiver must compute identical AAD for
    /// the AEAD verification to succeed.
    pub(crate) fn build_aad(&self, shard_index: ShardIndex) -> [u8; AAD_SIZE] {
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

    /// Write a complete FIUDP packet into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`FiudpError::InvalidShardSize`] if `payload.len() != SHARD_SIZE`.
    pub(crate) fn write_packet(
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

// -----------------------------------------------------------------------
// Padding helper
// -----------------------------------------------------------------------

/// Zero-pad `buf` so its length is a multiple of [`SHARD_SIZE`].
///
/// If `buf.len()` is already a multiple, this is a no-op.
/// Otherwise, `0x00` bytes are appended until the next multiple
/// boundary is reached.
///
/// This is required by the FIUDP spec (§3.2): "The frame byte stream
/// is padded with zeros to a multiple of 1400."
pub(crate) fn pad_to_shard_size(buf: &mut Vec<u8>) {
    let rem = buf.len() % SHARD_SIZE;
    if rem == 0 {
        return;
    }

    let new_len = buf.len() + (SHARD_SIZE - rem);
    buf.resize(new_len, 0u8);
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

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
    fn packet_builder_writes_header_and_payload() {
        let builder = PacketBuilder::new(
            SessionId::new(0xABCD),
            RendezvousSecs::new(0x01020304),
            DataShardCount::new(0x0020),
            ParityShardCount::new(0x0004),
        );
        let mut packet = [0u8; PACKET_SIZE];
        let tag = [0x22; TAG_SIZE];
        let payload = vec![0x33; SHARD_SIZE];
        let aad = builder.build_aad(ShardIndex::new(0x1234));

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
        let builder = PacketBuilder::new(
            SessionId::new(0xABCD),
            RendezvousSecs::new(0),
            DataShardCount::new(1),
            ParityShardCount::new(0),
        );
        let mut packet = [0u8; PACKET_SIZE];
        let tag = [0u8; TAG_SIZE];
        let payload = vec![0u8; SHARD_SIZE - 1];
        let aad = builder.build_aad(ShardIndex::new(1));

        assert!(builder
            .write_packet(&mut packet, &aad, &tag, &payload)
            .is_err());
    }
}
