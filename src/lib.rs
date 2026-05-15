#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::Parser;
use reed_solomon_erasure::galois_8::ReedSolomon;

const SHARD_SIZE: usize = 1400;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const RENDEZVOUS_SIZE: usize = 4;
const SESSION_ID_SIZE: usize = 2;
const SHARD_INDEX_SIZE: usize = 2;
const DATA_SHARDS_SIZE: usize = 2;
const PARITY_SHARDS_SIZE: usize = 2;
const AAD_SIZE: usize =
    SESSION_ID_SIZE + SHARD_INDEX_SIZE + DATA_SHARDS_SIZE + PARITY_SHARDS_SIZE + RENDEZVOUS_SIZE;
const HEADER_SIZE: usize = AAD_SIZE + TAG_SIZE;
const PACKET_SIZE: usize = HEADER_SIZE + SHARD_SIZE;

const DEFAULT_UDP_PORT: u16 = 5050;
const DEFAULT_INTER_PACKET_DELAY_US: u64 = 500;

const SESSION_ID_OFFSET: usize = 0;
const SHARD_INDEX_OFFSET: usize = SESSION_ID_OFFSET + SESSION_ID_SIZE;
const DATA_SHARDS_OFFSET: usize = SHARD_INDEX_OFFSET + SHARD_INDEX_SIZE;
const PARITY_SHARDS_OFFSET: usize = DATA_SHARDS_OFFSET + DATA_SHARDS_SIZE;
const RENDEZVOUS_OFFSET: usize = PARITY_SHARDS_OFFSET + PARITY_SHARDS_SIZE;
const TAG_OFFSET: usize = RENDEZVOUS_OFFSET + RENDEZVOUS_SIZE;
const PAYLOAD_OFFSET: usize = TAG_OFFSET + TAG_SIZE;

#[derive(Parser, Debug)]
#[command(name = "fiudp-cli", version, about = "FIUDP unidirectional UDP sender")]
pub struct Args {
    /// Target IPv4 address of the TRMNL display
    #[arg(short = 't', long = "target", alias = "ip", value_name = "IP")]
    target: Ipv4Addr,

    /// Wake-up timer in seconds for the next sync cycle
    #[arg(
        short = 'w',
        long = "wake-at",
        alias = "rendezvous",
        value_name = "SECS"
    )]
    wake_at: u32,

    /// Path to the 256-bit (32 bytes) pre-shared key file
    #[arg(short = 'k', long = "key-file", value_name = "FILE")]
    key_file: PathBuf,

    /// Path to the raw input buffer file (fallback to STDIN if omitted)
    #[arg(short = 'i', long = "image", alias = "input", value_name = "FILE")]
    image: Option<PathBuf>,

    /// Percentage of parity shards to generate
    #[arg(
        short = 'p',
        long = "parity-ratio",
        default_value_t = 15,
        value_name = "PERCENT"
    )]
    parity_ratio: u8,

    /// UDP port of the TRMNL receiver
    #[arg(long, default_value_t = DEFAULT_UDP_PORT)]
    port: u16,

    /// Delay between packets in microseconds
    #[arg(long = "delay-us", default_value_t = DEFAULT_INTER_PACKET_DELAY_US)]
    delay_us: u64,
}

#[derive(Debug)]
pub struct Config {
    target_ip: Ipv4Addr,
    rendezvous_secs: u32,
    key_path: PathBuf,
    input: InputSource,
    parity_ratio: ParityRatio,
    target_port: u16,
    delay: Duration,
}

impl TryFrom<Args> for Config {
    type Error = anyhow::Error;

    fn try_from(args: Args) -> Result<Self> {
        let parity_ratio = ParityRatio::try_from(args.parity_ratio)?;
        let input = match args.image {
            Some(path) => InputSource::File(path),
            None => InputSource::Stdin,
        };

        Ok(Self {
            target_ip: args.target,
            rendezvous_secs: args.wake_at,
            key_path: args.key_file,
            input,
            parity_ratio,
            target_port: args.port,
            delay: Duration::from_micros(args.delay_us),
        })
    }
}

pub fn run(config: Config) -> Result<()> {
    let reader = config.input;
    let key_path = config.key_path.clone();
    let key_source = FileKeySource::new(config.key_path);
    let key = key_source.load_key()?;
    let session_id = SessionIdStore::new(&key_path).next()?;

    let encryptor = ChaChaEncryptor::new(key);
    let fec = ReedSolomonEngine;
    let sender = UdpPacketSender::new(config.target_ip, config.target_port)?;

    let pipeline = FiudpSender::new(reader, fec, encryptor, sender, config.delay);

    pipeline.send(config.parity_ratio, config.rendezvous_secs, session_id)
}

#[derive(Clone, Copy, Debug)]
struct ParityRatio(u8);

impl ParityRatio {
    fn parity_shards(self, data_shards: usize) -> usize {
        if self.0 == 0 {
            return 0;
        }

        let numerator = data_shards.saturating_mul(self.0 as usize);
        numerator.div_ceil(100)
    }
}

impl TryFrom<u8> for ParityRatio {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        if value > 100 {
            bail!("parity ratio must be between 0 and 100");
        }

        Ok(Self(value))
    }
}

#[derive(Debug)]
enum InputSource {
    File(PathBuf),
    Stdin,
}

trait InputReader {
    fn read_all(&self) -> Result<Vec<u8>>;
}

impl InputReader for InputSource {
    fn read_all(&self) -> Result<Vec<u8>> {
        match self {
            InputSource::File(path) => fs::read(path)
                .with_context(|| format!("failed to read input file {}", path.display())),
            InputSource::Stdin => {
                let mut buf = Vec::new();
                io::stdin()
                    .lock()
                    .read_to_end(&mut buf)
                    .context("failed to read from stdin")?;
                Ok(buf)
            }
        }
    }
}

trait KeySource {
    fn load_key(&self) -> Result<[u8; 32]>;
}

struct FileKeySource {
    path: PathBuf,
}

impl FileKeySource {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl KeySource for FileKeySource {
    fn load_key(&self) -> Result<[u8; 32]> {
        read_key(&self.path)
    }
}

struct SessionIdStore {
    path: PathBuf,
}

impl SessionIdStore {
    fn new(key_path: &Path) -> Self {
        let mut path = key_path.to_path_buf();
        path.set_extension("session_id");
        Self { path }
    }

    fn next(&self) -> Result<u16> {
        let current = match fs::read(&self.path) {
            Ok(bytes) => {
                if bytes.len() != 2 {
                    bail!(
                        "session_id file {} must contain exactly 2 bytes",
                        self.path.display()
                    );
                }
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&bytes);
                Some(u16::from_be_bytes(buf))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to read session_id file {}", self.path.display())
                })
            }
        };

        let next = match current {
            Some(value) => value.checked_add(1).ok_or_else(|| {
                anyhow!("session_id overflow; rotate PSK and reset receiver state")
            })?,
            None => 1,
        };

        fs::write(&self.path, next.to_be_bytes())
            .with_context(|| format!("failed to write session_id file {}", self.path.display()))?;

        Ok(next)
    }
}

trait FecEngine {
    fn encode(
        &self,
        data_shards: usize,
        parity_shards: usize,
        shards: &mut [&mut [u8]],
    ) -> Result<()>;
}

struct ReedSolomonEngine;

impl FecEngine for ReedSolomonEngine {
    fn encode(
        &self,
        data_shards: usize,
        parity_shards: usize,
        shards: &mut [&mut [u8]],
    ) -> Result<()> {
        let rse = ReedSolomon::new(data_shards, parity_shards)
            .context("failed to initialize Reed-Solomon encoder")?;
        rse.encode(shards)
            .context("failed to generate parity shards")?;
        Ok(())
    }
}

trait Encryptor {
    fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_SIZE]>;
}

struct ChaChaEncryptor {
    cipher: ChaCha20Poly1305,
}

impl ChaChaEncryptor {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
        }
    }
}

impl Encryptor for ChaChaEncryptor {
    fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_SIZE]> {
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer)
            .map_err(|err| anyhow!("encryption failed: {err:?}"))?;

        let mut tag_bytes = [0u8; TAG_SIZE];
        tag_bytes.copy_from_slice(tag.as_slice());
        Ok(tag_bytes)
    }
}

struct PacketBuilder {
    session_id: u16,
    rendezvous_secs: u32,
    data_shards: u16,
    parity_shards: u16,
}

impl PacketBuilder {
    fn new(session_id: u16, rendezvous_secs: u32, data_shards: u16, parity_shards: u16) -> Self {
        Self {
            session_id,
            rendezvous_secs,
            data_shards,
            parity_shards,
        }
    }

    fn build_aad(&self, shard_index: u16) -> [u8; AAD_SIZE] {
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

    fn write_packet(
        &self,
        out: &mut [u8; PACKET_SIZE],
        aad: &[u8; AAD_SIZE],
        tag: &[u8; TAG_SIZE],
        payload: &[u8],
    ) -> Result<()> {
        if payload.len() != SHARD_SIZE {
            bail!(
                "invalid shard size {}, expected {}",
                payload.len(),
                SHARD_SIZE
            );
        }

        out[..AAD_SIZE].copy_from_slice(aad);
        out[TAG_OFFSET..TAG_OFFSET + TAG_SIZE].copy_from_slice(tag);
        out[PAYLOAD_OFFSET..PAYLOAD_OFFSET + SHARD_SIZE].copy_from_slice(payload);

        Ok(())
    }
}

trait PacketSender {
    fn send(&self, packet: &[u8]) -> Result<()>;
}

struct UdpPacketSender {
    socket: UdpSocket,
    target: SocketAddrV4,
}

impl UdpPacketSender {
    fn new(target_ip: Ipv4Addr, port: u16) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind UDP socket")?;
        let target = SocketAddrV4::new(target_ip, port);
        socket
            .connect(target)
            .with_context(|| format!("failed to connect UDP socket to {}", target))?;

        Ok(Self { socket, target })
    }
}

impl PacketSender for UdpPacketSender {
    fn send(&self, packet: &[u8]) -> Result<()> {
        let sent = self
            .socket
            .send(packet)
            .with_context(|| format!("failed to send UDP packet to {}", self.target))?;
        if sent != packet.len() {
            bail!("short UDP send: {} of {} bytes", sent, packet.len());
        }

        Ok(())
    }
}

struct FiudpSender<R, F, E, S> {
    reader: R,
    fec: F,
    encryptor: E,
    sender: S,
    delay: Duration,
}

impl<R, F, E, S> FiudpSender<R, F, E, S>
where
    R: InputReader,
    F: FecEngine,
    E: Encryptor,
    S: PacketSender,
{
    fn new(reader: R, fec: F, encryptor: E, sender: S, delay: Duration) -> Self {
        Self {
            reader,
            fec,
            encryptor,
            sender,
            delay,
        }
    }

    fn send(&self, parity_ratio: ParityRatio, rendezvous_secs: u32, session_id: u16) -> Result<()> {
        let mut payload = self.reader.read_all()?;
        if payload.is_empty() {
            bail!("input is empty");
        }

        pad_to_shard_size(&mut payload);

        let data_shards = payload.len() / SHARD_SIZE;
        if data_shards == 0 {
            bail!("input is empty after padding");
        }

        let parity_shards = parity_ratio.parity_shards(data_shards);
        let total_shards = data_shards + parity_shards;

        if total_shards > u16::MAX as usize {
            bail!("total shards {} exceeds u16 limit", total_shards);
        }

        let data_shards_u16 =
            u16::try_from(data_shards).context("data_shards exceeds u16 limit")?;
        let parity_shards_u16 =
            u16::try_from(parity_shards).context("parity_shards exceeds u16 limit")?;

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
        let mut packet = [0u8; PACKET_SIZE];

        let shard_count = shards.len();
        for (index, shard_ref) in shards.iter_mut().enumerate() {
            let shard = &mut **shard_ref;
            debug_assert_eq!(shard.len(), SHARD_SIZE);

            let nonce = derive_nonce(session_id, index as u16);

            let aad = packet_builder.build_aad(index as u16);
            let tag = self.encryptor.encrypt_in_place(&nonce, &aad, shard)?;

            packet_builder.write_packet(&mut packet, &aad, &tag, shard)?;
            self.sender.send(&packet)?;

            if index + 1 < shard_count {
                thread::sleep(self.delay);
            }
        }

        Ok(())
    }
}

fn pad_to_shard_size(buf: &mut Vec<u8>) {
    let rem = buf.len() % SHARD_SIZE;
    if rem == 0 {
        return;
    }

    let new_len = buf.len() + (SHARD_SIZE - rem);
    buf.resize(new_len, 0u8);
}

fn derive_nonce(session_id: u16, shard_index: u16) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..2].copy_from_slice(&session_id.to_be_bytes());
    nonce[2..4].copy_from_slice(&shard_index.to_be_bytes());
    nonce
}

fn read_key(path: &Path) -> Result<[u8; 32]> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read key file {}", path.display()))?;
    if bytes.len() != 32 {
        bail!("key file must contain exactly 32 bytes");
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

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
    fn parity_ratio_validation() {
        assert!(ParityRatio::try_from(0).is_ok());
        assert!(ParityRatio::try_from(100).is_ok());
        assert!(ParityRatio::try_from(101).is_err());
    }

    #[test]
    fn parity_ratio_rounds_up() {
        let ratio = ParityRatio::try_from(15).unwrap();
        assert_eq!(ratio.parity_shards(10), 2);
        assert_eq!(ratio.parity_shards(1), 1);
        assert_eq!(ratio.parity_shards(0), 0);
    }

    #[test]
    fn packet_builder_writes_header_and_payload() {
        let builder = PacketBuilder::new(0xABCD, 0x01020304, 0x0020, 0x0004);
        let mut packet = [0u8; PACKET_SIZE];
        let tag = [0x22; TAG_SIZE];
        let payload = vec![0x33; SHARD_SIZE];
        let aad = builder.build_aad(0x1234);

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
        let builder = PacketBuilder::new(0xABCD, 0, 1, 0);
        let mut packet = [0u8; PACKET_SIZE];
        let tag = [0u8; TAG_SIZE];
        let payload = vec![0u8; SHARD_SIZE - 1];
        let aad = builder.build_aad(1);

        assert!(builder
            .write_packet(&mut packet, &aad, &tag, &payload)
            .is_err());
    }
}
