# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0]

### Added
- Semantic newtypes for wire-format fields: `SessionId`, `ShardIndex`, `DataShardCount`, `ParityShardCount`, `RendezvousSecs`. Prevents accidental misuse of bare `u16`/`u32` values at compile time.
- Exhaustive `///` documentation on all internal items: traits (`Encryptor`, `FecEngine`, `PacketSender`, `InputReader`, `KeySource`), structs (`PacketBuilder`, `FiudpSender`, `SessionIdStore`, `ChaChaEncryptor`, etc.), and helper functions (`derive_nonce`, `pad_to_shard_size`, `read_key`).
- Module organisation table in the crate-level rustdoc.
- Documented `FiudpSender` type parameters (`R`, `F`, `E`, `S`) in rustdoc.

### Changed
- Split monolithic `lib.rs` (1 030 lines) into 8 focused modules: `error`, `types`, `protocol`, `crypto`, `fec`, `session`, `config`, `sender`.
- `PacketBuilder`, `derive_nonce`, `SessionIdStore::next` now accept/return newtypes instead of raw primitives.
- Tests migrated to their respective modules (`protocol::tests`, `config::tests`).

### Fixed
- Nothing. This is a pure refactoring with no behavioural changes.

## [0.1.0]

### Added
- Full rustdoc coverage: crate-level docs, all public items, wire-format constants.
- `FiudpError` typed error enum replacing opaque `anyhow::Error` in the public API.
- `ConfigBuilder` for programmatic construction without clap parsing.
- `#![warn(missing_docs)]` lint guard to prevent future documentation regressions.
- `examples/send_frame.rs` showing library usage.
- `CHANGELOG.md` (this file).
- Cargo.toml metadata: `keywords`, `categories`, `rust-version`.

### Changed
- All wire-format constants (`SHARD_SIZE`, offsets, etc.) are now `pub` for receiver implementors.
- `Cargo.toml` description updated for better docs.rs rendering.
- `rust-version` set to `1.73` (minimum required by `div_ceil`).

### Removed
- `anyhow` dependency (replaced by `thiserror` for the library, manual error printing in the binary).
- Unused `rand` dependency.

