# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
