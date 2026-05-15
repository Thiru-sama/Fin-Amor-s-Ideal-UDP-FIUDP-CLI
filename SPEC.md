# SPEC - Protocol and Architecture Specification

## 0. Status, Scope, and Terminology
Status: Draft

Scope:
- Define the end-to-end pipeline from HTML layouts to BMP artifacts.
- Specify the FIUDP transport framing used to deliver images to a TRMNL-class terminal.
- Define security, error handling, and power behavior.

Terminology:
- MUST, SHOULD, MAY are to be interpreted as in RFC 2119.
- Sender: the FIUDP CLI or any compatible transmitter.
- Terminal: the e-paper display device that receives and renders frames.
- Frame: the complete BMP byte stream representing a single screen update.
- Shard: a fixed-size fragment of the frame used for FEC and transport.
- Session: a single one-way transmission burst.
- Rendezvous: seconds until the next wake window.

## 1. Core Philosophy and Design Principles

### 1.1 Hyper-Efficiency
- One burst per frame: the sender transmits once, then exits.
- Fixed packet size and fixed shard size allow tight receiver buffers and deterministic timing.
- No broker, no handshake, no keep-alive traffic.
- FEC trades a small, bounded bandwidth increase for fewer retries and less radio time.

### 1.2 Zero-Trust Security
- Every shard is authenticated and encrypted with ChaCha20-Poly1305 and a 256-bit pre-shared key (PSK).
- Metadata that affects rendering or scheduling is authenticated as AEAD AAD to prevent tampering.
- The receiver rejects unauthenticated shards without side effects and without state promotion.
- The protocol is stateless and does not trust the network or transport.

### 1.3 User Respect and Ethics
- Local-first: no telemetry, no vendor cloud, no background data flows.
- No dependency on third-party brokers or opaque SaaS services.
- Privacy by design: no identifiers beyond the PSK and session-local metadata.
- Hardware longevity: avoid hot radios, avoid excessive write cycles, and prefer deterministic wake windows.

## 2. System Overview

Data flow:
1) HTML/CSS template is rendered to a pixel-accurate raster.
2) Raster is converted into a constrained BMP artifact.
3) BMP bytes are segmented into fixed-size shards.
4) Shards are FEC-encoded, encrypted, and sent over UDP.
5) Terminal reassembles, validates, decodes, and renders the frame.

Components:
- Composer: produces the HTML/CSS template and assets.
- Compiler: renders HTML to BMP deterministically.
- Sender: FIUDP CLI that transmits a frame.
- Terminal: validates and displays the frame.

## 3. HTML-to-BMP Pipeline Specification

### 3.1 Inputs and Constraints
- All assets MUST be local files. No network fetches are allowed.
- Fonts MUST be pinned and bundled with the template to ensure deterministic glyph metrics.
- JavaScript MUST be disabled or restricted to pure, deterministic layout logic.
- The viewport MUST match the terminal resolution and orientation exactly.
- Device pixel ratio MUST be 1.0.

### 3.2 Rendering Rules
- Rendering MUST be headless and deterministic for the same inputs.
- Default background MUST be solid white (#FFFFFF) unless explicitly set.
- Subpixel rendering MUST be disabled; use whole-pixel rasterization.
- Color space MUST be sRGB for inputs, then converted to linear luminance for quantization.

### 3.3 Quantization and Dithering
- Convert RGB to linear luminance using standard sRGB transfer.
- Monochrome output uses a fixed threshold or ordered dithering.
- Grayscale output uses 4-bit (16 levels) quantization with optional error diffusion.
- Dithering is permitted but MUST be deterministic.

### 3.4 BMP Output Requirements

Canonical output is Windows BMP v3 (BITMAPINFOHEADER), uncompressed.

Required properties:
- Byte order: little-endian for all header fields.
- Compression: BI_RGB (0), no compression.
- Resolution: fixed to the terminal panel dimensions.
- Orientation: top-down DIB (negative height) to avoid vertical flip.

Bit depth:
- MUST support 1-bit monochrome.
- MAY support 4-bit grayscale (16 levels).

Row padding:
- Each row MUST be padded to a 4-byte boundary.

BMP file structure:

| Section | Size (bytes) | Notes |
| --- | --- | --- |
| BITMAPFILEHEADER | 14 | Standard BMP file header |
| BITMAPINFOHEADER | 40 | DIB header (v3) |
| Color Table | 8 or 64 | 2 entries for 1-bit, 16 entries for 4-bit |
| Pixel Array | variable | Rows padded to 4-byte boundary |

BITMAPFILEHEADER layout:

| Offset | Size | Field | Value |
| --- | --- | --- | --- |
| 0 | 2 | bfType | 0x4D42 ("BM") |
| 2 | 4 | bfSize | Total file size |
| 6 | 2 | bfReserved1 | 0 |
| 8 | 2 | bfReserved2 | 0 |
| 10 | 4 | bfOffBits | Pixel array offset |

BITMAPINFOHEADER layout:

| Offset | Size | Field | Value |
| --- | --- | --- | --- |
| 0 | 4 | biSize | 40 |
| 4 | 4 | biWidth | Panel width (pixels) |
| 8 | 4 | biHeight | Negative panel height (pixels) |
| 12 | 2 | biPlanes | 1 |
| 14 | 2 | biBitCount | 1 or 4 |
| 16 | 4 | biCompression | 0 (BI_RGB) |
| 20 | 4 | biSizeImage | Pixel array size |
| 24 | 4 | biXPelsPerMeter | 0 |
| 28 | 4 | biYPelsPerMeter | 0 |
| 32 | 4 | biClrUsed | 0 (default) |
| 36 | 4 | biClrImportant | 0 |

Color table:
- 1-bit: [0x00,0x00,0x00,0x00] for black and [0xFF,0xFF,0xFF,0x00] for white.
- 4-bit: 16 entries from black to white in linear luminance order.

### 3.5 Frame Byte Stream
- The transmitted frame is the raw BMP byte stream as produced above.
- No additional container or metadata is prefixed.
- Frame length is therefore deterministic for a given resolution and bit depth.

## 4. FIUDP Protocol Specification (v1)

### 4.1 Transport and Session Model
- Transport is UDP, unidirectional.
- Default port is 5050.
- A session is a single burst of packets carrying one full frame.
- The sender does not wait for acknowledgements by default.

### 4.2 Sharding and FEC
- Shard size is fixed at 1400 bytes.
- The frame byte stream is padded with zeros to a multiple of 1400.
- data_shards = frame_len / 1400.
- parity_shards = ceil(data_shards * parity_ratio / 100).
- total_shards = data_shards + parity_shards (MUST be <= 65535).
- Reed-Solomon over GF(2^8) is used to generate parity shards.
- Parity ratio is provisioned out-of-band (CLI config and terminal config MUST match).

### 4.3 Cryptographic Envelope
- AEAD: ChaCha20-Poly1305.
- Key: 32-byte PSK, provisioned out-of-band.
- Nonce: 12 bytes, unique per shard within a key.
- AAD: session_id, shard_index, rendezvous_secs (8 bytes total).
- The AEAD tag is 16 bytes and appended in the packet header.

### 4.4 Packet Format
Each UDP packet is exactly 1436 bytes.

| Offset | Size | Field | Encoding | Authenticated | Encrypted |
| --- | --- | --- | --- | --- | --- |
| 0 | 2 | session_id | u16, big-endian | Yes (AAD) | No |
| 2 | 2 | shard_index | u16, big-endian | Yes (AAD) | No |
| 4 | 4 | rendezvous_secs | u32, big-endian | Yes (AAD) | No |
| 8 | 12 | nonce | 96-bit random | No | No |
| 20 | 16 | tag | Poly1305 tag | No | No |
| 36 | 1400 | payload | shard ciphertext | Yes (AEAD) | Yes |

Notes:
- session_id groups shards belonging to the same frame transmission.
- shard_index is a 0-based index across data and parity shards.
- rendezvous_secs communicates the next intended wake window.
- There is no version or magic field to minimize overhead.

### 4.5 Receiver Behavior
- The receiver MUST validate the AEAD tag before accepting a shard.
- Shards with invalid tags MUST be discarded silently.
- The receiver MUST group shards by session_id and shard_index.
- data_shards and parity_shards are derived from known frame length and configured parity ratio.
- When sufficient shards are present, the receiver MUST attempt FEC recovery.
- If recovery fails, the receiver MUST keep the previous frame and schedule the next wake.

Rendezvous handling:
- rendezvous_secs is advisory and represents the next desired wake time in seconds.
- A value of 0 indicates no change to the existing wake schedule.

### 4.6 Optional Receipt Response
A receipt is OPTIONAL and intended for lab or debugging use. Production deployments SHOULD disable receipts to minimize radio time.

Receipt packet (if used):

| Offset | Size | Field | Encoding |
| --- | --- | --- | --- |
| 0 | 2 | session_id | u16, big-endian |
| 2 | 1 | status | 0x00 ok, 0x01 decode_fail, 0x02 auth_fail |
| 3 | 1 | reason | implementation-defined |
| 4 | 2 | shards_ok | u16 |
| 6 | 2 | shards_needed | u16 |
| 8 | 4 | next_wake_secs | u32 |
| 12 | 12 | nonce | 96-bit random |
| 24 | 16 | tag | AEAD tag |

Receipt security:
- The receipt payload (bytes 0-11) MUST be authenticated with ChaCha20-Poly1305.
- The same PSK is used; AAD is session_id (2 bytes).

### 4.7 Error Handling and Power Discipline
- The sender does not retransmit; FEC is the primary loss mitigation.
- The receiver SHOULD keep its radio on only for a bounded window sized to total_shards and inter-packet delay.
- On failure, the receiver SHOULD preserve the previous frame and report the failure locally (optional).
- The system MUST avoid indefinite awake states or network retries.

## 5. Architecture and Directory Layout

Target repository layout:

```
/README.md
/SPEC.md
/assets/
/src/
  lib.rs
  main.rs
/compiler/
  renderer/
  quantizer/
  bmp/
/protocol/
  fiudp/
/spec/
  fixtures/
/examples/
  html/
  bmp/
/tools/
```

Directory intent:
- /compiler contains the HTML-to-BMP pipeline implementation.
- /protocol contains transport-level parsers and validators.
- /spec contains test vectors, fixtures, and conformance data.
- /examples contains reference HTML templates and known-good BMP outputs.

## 6. Conformance Targets
- A compliant sender MUST produce packets that match the byte layout in section 4.4.
- A compliant terminal MUST reject unauthenticated shards and MUST validate AAD.
- A compliant compiler MUST generate BMPs matching section 3.4.

## 7. Security Notes
- Nonce uniqueness is critical. Implementations MUST ensure no reuse under the same key.
- Keys MUST be provisioned out-of-band and rotated by a trusted process.
- Side-channel metadata (IP, timing) is not hidden by the protocol and MUST be considered in threat models.
