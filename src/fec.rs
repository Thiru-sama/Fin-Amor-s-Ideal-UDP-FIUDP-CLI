//! Forward Error Correction (FEC) engine for the FIUDP sender.
//!
//! FIUDP uses **Reed-Solomon erasure coding** over GF(2⁸) to generate
//! parity shards that allow the receiver to reconstruct the original
//! frame even if some UDP packets are lost in transit.
//!
//! This module defines the [`FecEngine`] trait (for testability) and
//! its production implementation [`ReedSolomonEngine`] backed by the
//! `reed-solomon-erasure` crate.
//!
//! See SPEC.md §3.2 for the sharding and FEC specification.

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::error::{FiudpError, Result};

// -----------------------------------------------------------------------
// FecEngine trait
// -----------------------------------------------------------------------

/// Abstraction over erasure-code encoding for testability.
///
/// The production implementation ([`ReedSolomonEngine`]) delegates to
/// the `reed-solomon-erasure` crate. Tests can substitute a no-op or
/// deterministic implementation.
pub(crate) trait FecEngine {
    /// Encode parity shards in-place.
    ///
    /// `shards` contains `data_shards` data slices followed by
    /// `parity_shards` zero-initialised parity slices. On success,
    /// the parity slices are filled with the computed redundancy data.
    ///
    /// # Errors
    ///
    /// Returns [`FiudpError::Fec`] if the encoder cannot be initialised
    /// (e.g. invalid shard counts) or if encoding fails.
    fn encode(
        &self,
        data_shards: usize,
        parity_shards: usize,
        shards: &mut [&mut [u8]],
    ) -> Result<()>;
}

// -----------------------------------------------------------------------
// ReedSolomonEngine
// -----------------------------------------------------------------------

/// Production [`FecEngine`] using Reed-Solomon over GF(2⁸).
///
/// This is a zero-size type — the Reed-Solomon encoder is constructed
/// fresh for each session since the shard counts can vary.
pub(crate) struct ReedSolomonEngine;

impl FecEngine for ReedSolomonEngine {
    fn encode(
        &self,
        data_shards: usize,
        parity_shards: usize,
        shards: &mut [&mut [u8]],
    ) -> Result<()> {
        let rse = ReedSolomon::new(data_shards, parity_shards).map_err(|e| {
            FiudpError::Fec(format!("failed to initialize Reed-Solomon encoder: {e}"))
        })?;
        rse.encode(shards)
            .map_err(|e| FiudpError::Fec(format!("failed to generate parity shards: {e}")))?;
        Ok(())
    }
}
