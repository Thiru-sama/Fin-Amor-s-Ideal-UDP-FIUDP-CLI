//! Packet sending and the FIUDP transmission pipeline.
//!
//! This module contains the transport abstraction ([`PacketSender`]),
//! its production UDP implementation ([`UdpPacketSender`]), and the
//! main orchestrator ([`FiudpSender`]) that ties together reading,
//! FEC encoding, encryption, and sending into a single burst.
//!
//! ## Pipeline overview
//!
//! ```text
//! ┌──────────┐    ┌──────────┐    ┌───────────┐    ┌──────────┐
//! │  Reader  │───▶│   FEC    │───▶│ Encryptor │───▶│  Sender  │
//! │ (R)      │    │ (F)      │    │ (E)       │    │ (S)      │
//! └──────────┘    └──────────┘    └───────────┘    └──────────┘
//!   frame bytes    + parity       + AEAD tag        → UDP
//! ```

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::Duration;

use crate::config::{InputReader, ParityRatio};
use crate::crypto::{derive_nonce, Encryptor};
use crate::error::{FiudpError, Result};
use crate::fec::FecEngine;
use crate::protocol::{pad_to_shard_size, PacketBuilder, PACKET_SIZE, SHARD_SIZE};
use crate::types::{DataShardCount, ParityShardCount, RendezvousSecs, SessionId, ShardIndex};

// -----------------------------------------------------------------------
// PacketSender trait
// -----------------------------------------------------------------------

/// Abstraction over the outbound transport for testability.
///
/// The production implementation ([`UdpPacketSender`]) sends over a real
/// UDP socket. Tests can substitute a `Vec<Vec<u8>>` collector or a
/// no-op sender.
pub trait PacketSender {
    /// Send a single FIUDP packet.
    ///
    /// `packet` is always exactly [`PACKET_SIZE`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FiudpError::Io`] on OS-level send failure, or
    /// [`FiudpError::ShortSend`] if the OS reports fewer bytes sent
    /// than the full packet.
    fn send(&self, packet: &[u8]) -> Result<()>;
}

// -----------------------------------------------------------------------
// UdpPacketSender
// -----------------------------------------------------------------------

/// Production [`PacketSender`] that transmits over a UDP socket.
///
/// The socket is bound to `0.0.0.0:0` (OS-assigned ephemeral port)
/// and connected to the target address, so subsequent `send()` calls
/// do not need to specify the destination.
pub struct UdpPacketSender {
    /// The bound and connected UDP socket.
    socket: UdpSocket,
    /// The target address (for error messages).
    target: SocketAddrV4,
}

impl UdpPacketSender {
    /// Create a new sender targeting the given IP and port.
    ///
    /// Binds to an ephemeral local port and connects to the target.
    ///
    /// # Errors
    ///
    /// Returns [`FiudpError::Io`] if the socket cannot be bound or connected.
    pub fn new(target_ip: Ipv4Addr, port: u16) -> Result<Self> {
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
        let sent = self.socket.send(packet).map_err(|e| FiudpError::Io {
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

// -----------------------------------------------------------------------
// FiudpSender
// -----------------------------------------------------------------------

/// Orchestrates the full FIUDP send pipeline for a single session.
///
/// `FiudpSender` is generic over its four dependencies, which are
/// injected at construction time. This allows each component to be
/// tested in isolation and swapped out in integration tests.
///
/// # Type Parameters
///
/// - `R`: [`InputReader`] — source of the raw frame bytes (file or stdin).
/// - `F`: [`FecEngine`] — Reed-Solomon encoder for parity generation.
/// - `E`: [`Encryptor`] — ChaCha20-Poly1305 AEAD cipher for shard encryption.
/// - `S`: [`PacketSender`] — transport layer for outbound UDP packets.
///
/// # Lifetime
///
/// A `FiudpSender` is consumed by a single call to [`send`](Self::send).
/// For multiple transmissions, create a new instance each time (the
/// session ID is managed externally by [`crate::session::SessionIdStore`]).
pub struct FiudpSender<R, F, E, S> {
    /// The input reader providing frame bytes.
    reader: R,
    /// The FEC encoder for parity generation.
    fec: F,
    /// The AEAD encryptor for shard-level encryption.
    encryptor: E,
    /// The transport sender for outbound packets.
    sender: S,
    /// Delay injected between consecutive packet sends.
    delay: Duration,
    /// Percentage of packets to drop.
    chaos_drop: u8,
    /// Number of consecutive packets to drop.
    chaos_burst: u32,
    /// Whether to shuffle packets before sending.
    chaos_shuffle: bool,
}

impl<R, F, E, S> FiudpSender<R, F, E, S>
where
    R: InputReader,
    F: FecEngine,
    E: Encryptor,
    S: PacketSender,
{
    /// Create a new sender with the given dependencies.
    pub fn new(
        reader: R,
        fec: F,
        encryptor: E,
        sender: S,
        delay: Duration,
        chaos_drop: u8,
        chaos_burst: u32,
        chaos_shuffle: bool,
    ) -> Self {
        Self {
            reader,
            fec,
            encryptor,
            sender,
            delay,
            chaos_drop,
            chaos_burst,
            chaos_shuffle,
        }
    }

    /// Execute the send pipeline: read → pad → FEC → encrypt → transmit.
    ///
    /// # Steps
    ///
    /// 1. Read the entire frame from `reader`.
    /// 2. Zero-pad to a multiple of [`SHARD_SIZE`].
    /// 3. Compute parity shards via the [`FecEngine`].
    /// 4. For each shard (data then parity):
    ///    a. Derive the deterministic nonce.
    ///    b. Build the AAD from the packet header fields.
    ///    c. Encrypt the shard in-place and obtain the AEAD tag.
    ///    d. Assemble and send the complete packet.
    ///    e. Sleep for `delay` before the next packet (except after the last).
    ///
    /// # Errors
    ///
    /// Propagates errors from any stage of the pipeline.
    pub fn send(
        &self,
        parity_ratio: ParityRatio,
        rendezvous_secs: RendezvousSecs,
        session_id: SessionId,
    ) -> Result<()> {
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

        // Safe: guarded by the u16::MAX check above.
        let data_shards_u16 = DataShardCount::new(data_shards as u16);
        let parity_shards_u16 = ParityShardCount::new(parity_shards as u16);

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
        let mut ready_packets = Vec::with_capacity(shards.len());

        for (index, shard_ref) in shards.iter_mut().enumerate() {
            let shard = &mut **shard_ref;
            debug_assert_eq!(shard.len(), SHARD_SIZE);

            let shard_index = ShardIndex::new(index as u16);
            let nonce = derive_nonce(session_id, shard_index);

            let aad = packet_builder.build_aad(shard_index);
            let tag = self.encryptor.encrypt_in_place(&nonce, &aad, shard)?;

            let mut packet = [0u8; PACKET_SIZE];
            packet_builder.write_packet(&mut packet, &aad, &tag, shard)?;
            ready_packets.push(packet);
        }

        if self.chaos_burst > 0 {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let max_start = ready_packets.len().saturating_sub(self.chaos_burst as usize);
            if !ready_packets.is_empty() {
                let start_idx = rng.gen_range(0..=max_start);
                let end_idx = std::cmp::min(ready_packets.len(), start_idx + self.chaos_burst as usize);
                ready_packets.drain(start_idx..end_idx);
            }
        }

        if self.chaos_drop > 0 {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            ready_packets.retain(|_| rng.gen_range(0..100) >= self.chaos_drop);
        }

        if self.chaos_shuffle {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            ready_packets.shuffle(&mut rng);
        }

        let packet_count = ready_packets.len();
        for (i, packet) in ready_packets.into_iter().enumerate() {
            self.sender.send(&packet)?;

            if i + 1 < packet_count {
                thread::sleep(self.delay);
            }
        }

        Ok(())
    }
}
