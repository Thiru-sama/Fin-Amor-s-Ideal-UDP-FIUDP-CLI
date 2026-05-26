//! Semantic newtypes for FIUDP wire-format fields.
//!
//! These types wrap primitive integers to give compile-time meaning to
//! values that would otherwise be interchangeable `u16` / `u32` parameters.
//! Mixing up a `session_id` and a `shard_index` is a silent bug with bare
//! primitives; with newtypes, the compiler catches the mistake.
//!
//! All newtypes implement `Display`, `Copy`, and provide `.as_u16()` /
//! `.as_u32()` accessors plus `.to_be_bytes()` for wire serialisation.

use std::fmt;

// ---------------------------------------------------------------------------
// SessionId
// ---------------------------------------------------------------------------

/// A monotonically increasing session identifier (`u16`, big-endian on wire).
///
/// Each FIUDP transmission burst is assigned a unique session ID.
/// The receiver uses this value for replay protection: any shard whose
/// session ID is ≤ the highest accepted value is silently discarded.
///
/// See SPEC.md §3.1 and §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u16);

impl SessionId {
    /// Wrap a raw `u16` value into a [`SessionId`].
    #[inline]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the underlying `u16`.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Serialise to 2 bytes, big-endian (wire order).
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for SessionId {
    #[inline]
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<SessionId> for u16 {
    #[inline]
    fn from(id: SessionId) -> Self {
        id.0
    }
}

// ---------------------------------------------------------------------------
// ShardIndex
// ---------------------------------------------------------------------------

/// Zero-based index of a shard within a session (`u16`, big-endian on wire).
///
/// Shard indices run from `0` to `total_shards - 1`, covering both data
/// and parity shards. The index participates in deterministic nonce
/// derivation: `session_id (2) ‖ shard_index (2) ‖ 0x00…00 (8)`.
///
/// See SPEC.md §3.3 and §3.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardIndex(u16);

impl ShardIndex {
    /// Wrap a raw `u16` value into a [`ShardIndex`].
    #[inline]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the underlying `u16`.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Serialise to 2 bytes, big-endian (wire order).
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for ShardIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for ShardIndex {
    #[inline]
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<ShardIndex> for u16 {
    #[inline]
    fn from(idx: ShardIndex) -> Self {
        idx.0
    }
}

// ---------------------------------------------------------------------------
// DataShardCount
// ---------------------------------------------------------------------------

/// Number of data shards in a session (`u16`, big-endian on wire).
///
/// Equals `ceil(frame_length / SHARD_SIZE)` after zero-padding.
/// Carried in the authenticated header so the receiver knows the
/// FEC layout without out-of-band signalling.
///
/// See SPEC.md §3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataShardCount(u16);

impl DataShardCount {
    /// Wrap a raw `u16` value into a [`DataShardCount`].
    #[inline]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the underlying `u16`.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Serialise to 2 bytes, big-endian (wire order).
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for DataShardCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for DataShardCount {
    #[inline]
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<DataShardCount> for u16 {
    #[inline]
    fn from(count: DataShardCount) -> Self {
        count.0
    }
}

// ---------------------------------------------------------------------------
// ParityShardCount
// ---------------------------------------------------------------------------

/// Number of parity (redundancy) shards in a session (`u16`, big-endian on wire).
///
/// Computed as `ceil(data_shards × parity_ratio / 100)`.
/// Together with [`DataShardCount`], fully describes the Reed-Solomon
/// coding parameters for the session.
///
/// See SPEC.md §3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParityShardCount(u16);

impl ParityShardCount {
    /// Wrap a raw `u16` value into a [`ParityShardCount`].
    #[inline]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the underlying `u16`.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Serialise to 2 bytes, big-endian (wire order).
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for ParityShardCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for ParityShardCount {
    #[inline]
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<ParityShardCount> for u16 {
    #[inline]
    fn from(count: ParityShardCount) -> Self {
        count.0
    }
}

// ---------------------------------------------------------------------------
// RendezvousSecs
// ---------------------------------------------------------------------------

/// Seconds until the terminal's next wake window (`u32`, big-endian on wire).
///
/// This is an advisory value embedded in every packet header. A value of
/// `0` signals "no change" to the existing schedule. The receiver MAY
/// use this to set its next deep-sleep duration.
///
/// See SPEC.md §3.4 and §3.5 (Rendezvous handling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RendezvousSecs(u32);

impl RendezvousSecs {
    /// Wrap a raw `u32` value into a [`RendezvousSecs`].
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the underlying `u32`.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Serialise to 4 bytes, big-endian (wire order).
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for RendezvousSecs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0)
    }
}

impl From<u32> for RendezvousSecs {
    #[inline]
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<RendezvousSecs> for u32 {
    #[inline]
    fn from(secs: RendezvousSecs) -> Self {
        secs.0
    }
}
