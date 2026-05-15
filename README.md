# FIUDP CLI

Small, sharp Rust tool that streams a raw image to a TRMNL display IP over FIUDP. It applies FEC and AEAD encryption (ChaCha20-Poly1305) with a 256-bit pre-shared key, and is designed to compose well with other Unix tools.

![The Swing](assets/Fragonard_The_Swing.jpg)
_The Swing ("The Happy Accidents of the Swing"). Painting by Jean-Honoré Fragonard._  

## Table of contents
- [What it does](#what-it-does)
- [Install](#install)
- [Usage](#usage)
- [Configuration](#configuration)
- [Examples](#examples)
- [Design](#design)
- [Security](#security)
- [Build](#build)
- [Test](#test)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## What it does
- Reads a raw image from a file or stdin
- Applies FEC and authenticated encryption (ChaCha20-Poly1305) with a 256-bit pre-shared key
- Streams to a configured TRMNL display IP over FIUDP
- Exposes a clean CLI and exits with useful status codes

## Install

### From crates.io
```sh
cargo install fiudp-cli
```

### From source
```sh
git clone https://github.com/<org>/fiudp-cli.git
cd fiudp-cli
cargo install --path .
```

## Usage
```sh
fiudp --image ./frame.raw --wake-at 3600 --target 192.0.2.10
```

### Help
```sh
fiudp --help
```

## Configuration

CLI options:
- `--target` destination IPv4 address (alias: `--ip`)
- `--wake-at` wake timer in seconds for the next sync cycle (alias: `--rendezvous`)
- `--image` path to the raw input file (alias: `--input`, omit to read stdin)
- `--key-file` path to the 32-byte pre-shared key
- `--parity-ratio` percentage of parity shards to generate
- `--port` UDP port (default: 5050)
- `--delay-us` inter-packet delay in microseconds (default: 500)

## Examples

Stream from stdin:
```sh
cat frame.raw | fiudp --wake-at 3600 --target 192.0.2.10
```

Custom port and delay:
```sh
fiudp --image ./frame.raw --wake-at 1800 --target 192.0.2.10 --port 5051 --delay-us 1000
```

## Design

Unix principles:
- Do one thing well
- Compose with pipes
- Text-based config
- Predictable exit codes

FIUDP pipeline:
1) Read image
2) FEC encode
3) AEAD encrypt (ChaCha20-Poly1305) with authenticated header (AAD)
4) UDP stream to TRMNL

## Security
- ChaCha20-Poly1305 uses a 256-bit pre-shared key; this provides post-quantum resilience against Grover's algorithm, but it is not an asymmetric PQ KEM or "PQS suite"
- Packet headers are authenticated as AAD; tampering with session ID, shard index, or rendezvous timer should fail authentication on the receiver
- Prefer trusted networks; encryption does not prevent spoofing, metadata leakage, or DoS

## Build
```sh
cargo build --release
```

## Test
```sh
cargo test
```

## Contributing
- This is a personal tool; I am not actively accepting PRs
- Feel free to fork or reproduce it for your own needs
- Run `cargo fmt` and `cargo clippy` if you modify the code

## License
GNU GPL v3. See LICENSE.

## Acknowledgements
- TRMNL display ecosystem
- Rust community
