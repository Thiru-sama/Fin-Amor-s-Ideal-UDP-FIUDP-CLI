# SPEC - FIUDP Protocol and Sender Behavior

## 0. Status, Scope, and Terminology
Status: Draft

Scope:
- Define the FIUDP packet format, cryptographic envelope, and FEC framing.
- Define sender and receiver behavior for a one-way UNIX CLI sender.

Out of scope:
- HTML/CSS rendering, BMP conversion, and image semantics.
- Device UI, display driver internals, or panel tuning.
- Any broker-based or stateful transport.

Terminology:
- MUST, SHOULD, MAY are to be interpreted as in RFC 2119.
- Sender: a CLI process that reads bytes and transmits once.
- Terminal: the device that validates and displays a frame.
- Frame: the opaque byte stream provided by the caller.
- Shard: a fixed-size fragment of the frame used for FEC and transport.
- Session: a single one-way transmission burst.
- Rendezvous: seconds until the next wake window.

## 1. UNIX Design Principles
- Do one thing well: read a byte stream, FEC encode, encrypt, and send.
- Composability: upstream tools determine image format and content.
- Determinism: fixed packet size and bounded timing.
- Minimal state: no handshake, no daemon; only a monotonic session counter.

### 1.1 Why FIUDP for TRMNL-Class Terminals
- Purpose-built for one-way frame delivery to e-paper devices.
- Low power by design: one burst, bounded awake time, no broker.
- Secure-by-default: authenticated encryption per shard, replay protection.
- UNIX-friendly: pipes in, UDP out, zero runtime services.

### 1.2 Non-Goals
- Not a telemetry bus or pub/sub system.
- Not a general IoT protocol or broker replacement.
- Not a rendering or image format standard.
- Not bidirectional or stateful by default.

## 2. Data Model
- The sender treats the input frame as opaque bytes.
- The input MAY be a file or stdin.
- The frame is zero-padded to a multiple of the shard size.

### 2.1 Integration Summary (TRMNL and Similar Terminals)
1) Produce the terminal-native frame bytes (from any external renderer).
2) Provision a 32-byte PSK on sender and terminal.
3) Send the frame with the FIUDP sender.
4) Terminal validates, reconstructs, and displays or discards.

### 2.2 UNIX Composability Examples
Send a raw frame file:
```sh
fiudp --image ./frame.raw --wake-at 3600 --target 192.0.2.10 --key-file ./psk.bin
```

Stream from a pipeline:
```sh
cat ./frame.raw | fiudp --wake-at 1800 --target 192.0.2.10 --key-file ./psk.bin
```

Throttle and increase parity:
```sh
fiudp --image ./frame.raw --wake-at 3600 --target 192.0.2.10 --key-file ./psk.bin --parity-ratio 25 --delay-us 1000
```

### 2.3 Receiver Implementer Checklist
- Parse AAD header fields and derive the nonce from session_id and shard_index.
- Reject any shard that fails AEAD verification.
- Enforce monotonic session_id and persist the highest accepted value.
- Collect shards until FEC recovery is possible; then reconstruct the frame.
- If recovery fails, keep the previous frame and schedule the next wake.

## 3. FIUDP Protocol Specification (v1)

### 3.1 Transport and Session Model
- Transport is UDP, unidirectional.
- Default port is 5050.
- A session is a single burst of packets carrying one full frame.
- The sender does not wait for acknowledgements by default.
- The sender MUST use a strictly increasing session_id and persist it across runs.
- If session_id is close to wrap-around, the sender MUST rotate the PSK before reuse.

### 3.2 Sharding and FEC
- Shard size is fixed at 1400 bytes.
- The frame byte stream is padded with zeros to a multiple of 1400.
- data_shards = frame_len / 1400.
- parity_shards = ceil(data_shards * parity_ratio / 100).
- total_shards = data_shards + parity_shards (MUST be <= 65535).
- Reed-Solomon over GF(2^8) is used to generate parity shards.
- data_shards and parity_shards are carried in authenticated metadata per packet.
- parity_ratio MAY be changed per session; the receiver MUST use data_shards and parity_shards from the header.

### 3.3 Cryptographic Envelope
- AEAD: ChaCha20-Poly1305.
- Key: 32-byte PSK, provisioned out-of-band.
- Nonce: 12 bytes. For data packets, the nonce is deterministic: session_id (2) || shard_index (2) || 0x0000000000000000 (8). The nonce is not transmitted for data packets.
- AAD: session_id, shard_index, data_shards, parity_shards, rendezvous_secs (12 bytes total).
- The AEAD tag is 16 bytes and appended in the packet header.
- Receipt packets MAY use a random nonce and include it as specified in section 3.6.

### 3.4 Packet Format
Each UDP packet is exactly 1428 bytes.

| Offset | Size | Field | Encoding | Authenticated | Encrypted |
| --- | --- | --- | --- | --- | --- |
| 0 | 2 | session_id | u16, big-endian | Yes (AAD) | No |
| 2 | 2 | shard_index | u16, big-endian | Yes (AAD) | No |
| 4 | 2 | data_shards | u16, big-endian | Yes (AAD) | No |
| 6 | 2 | parity_shards | u16, big-endian | Yes (AAD) | No |
| 8 | 4 | rendezvous_secs | u32, big-endian | Yes (AAD) | No |
| 12 | 16 | tag | Poly1305 tag | No | No |
| 28 | 1400 | payload | shard ciphertext | Yes (AEAD) | Yes |

Notes:
- session_id groups shards belonging to the same frame transmission.
- shard_index is a 0-based index across data and parity shards.
- data_shards and parity_shards describe the FEC layout for the session.
- rendezvous_secs communicates the next intended wake window.
- nonce is derived from session_id and shard_index; it is not transmitted.
- There is no version or magic field to minimize overhead.

### 3.5 Receiver Behavior
- The receiver MUST validate the AEAD tag before accepting a shard.
- Shards with invalid tags MUST be discarded silently.
- The receiver MUST track the highest successfully processed session_id. Any shard belonging to a session_id less than or equal to the tracked value MUST be silently discarded to prevent replay attacks. Successfully processed means a frame was authenticated, reconstructed, and accepted for display.
- The receiver SHOULD persist the last accepted session_id across reboots where feasible.
- The receiver MUST group shards by session_id and shard_index.
- data_shards and parity_shards MUST be read from authenticated header metadata and MUST remain consistent across all shards in a session. Inconsistent values MUST be discarded.
- When sufficient shards are present, the receiver MUST attempt FEC recovery.
- If recovery fails, the receiver MUST keep the previous frame and schedule the next wake.

Rendezvous handling:
- rendezvous_secs is advisory and represents the next desired wake time in seconds.
- A value of 0 indicates no change to the existing wake schedule.

### 3.6 Optional Receipt Response
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

### 3.7 Error Handling and Power Discipline
- The sender does not retransmit; FEC is the primary loss mitigation.
- The receiver SHOULD keep its radio on only for a bounded window sized to total_shards and inter-packet delay.
- On failure, the receiver SHOULD preserve the previous frame and report the failure locally (optional).
- The system MUST avoid indefinite awake states or network retries.

## 4. Security Notes
- Nonce uniqueness is critical. For data packets, nonce derivation depends on session_id and shard_index, so session_id MUST NOT repeat under the same key and shard_index MUST be unique within a session.
- Keys MUST be provisioned out-of-band and rotated by a trusted process.
- Side-channel metadata (IP, timing) is not hidden by the protocol and MUST be considered in threat models.

## 5. Compatibility and Versioning
- FIUDP v1 is fixed-field and versioned out-of-band.
- Implementations SHOULD treat any format changes as a new spec version and update both endpoints together.

## 6. FAQ
Q: Does FIUDP define the image format?
A: No. FIUDP transports opaque bytes. Use whatever rendering pipeline produces the terminal-native frame.

Q: Is there a broker or handshake?
A: No. FIUDP is one-way UDP with optional receipts for lab use.

Q: Why not use MQTT or a generic IoT protocol?
A: FIUDP optimizes for minimal overhead, deterministic timing, and long deep-sleep cycles.
