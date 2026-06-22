use fiudp_cli::internals::{ChaChaEncryptor, FiudpSender, InputReader, PacketSender, ReedSolomonEngine, ParityRatio};
use fiudp_cli::types::{RendezvousSecs, SessionId};
use fiudp_cli::error::Result;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// A reader that provides a fixed-size dummy payload
struct DummyReader {
    size: usize,
}

impl InputReader for DummyReader {
    fn read_all(&self) -> Result<Vec<u8>> {
        Ok(vec![0x42; self.size])
    }
}

// A sender that just counts packets and total bytes instead of using the network
struct AccountingSender {
    packet_count: Arc<Mutex<usize>>,
    byte_count: Arc<Mutex<usize>>,
}

impl PacketSender for AccountingSender {
    fn send(&self, packet: &[u8]) -> Result<()> {
        let mut pc = self.packet_count.lock().unwrap();
        *pc += 1;
        
        let mut bc = self.byte_count.lock().unwrap();
        *bc += packet.len();
        
        Ok(())
    }
}

#[test]
fn test_network_footprint() {
    let payload_sizes = [5_000, 10_000, 48_000]; // 5KB, 10KB, 48KB (typical TRMNL images)
    let parity_percentages = [10, 25, 50]; // 10%, 25%, 50% FEC

    println!("\n=== FIUDP Network Footprint Analysis ===");
    println!("Payload Size | FEC Parity | Total Packets | Bytes Over-The-Air | Protocol Overhead");
    println!("---------------------------------------------------------------------------------");

    for &size in &payload_sizes {
        for &pct in &parity_percentages {
            let packet_count = Arc::new(Mutex::new(0));
            let byte_count = Arc::new(Mutex::new(0));

            let reader = DummyReader { size };
            let fec = ReedSolomonEngine;
            let encryptor = ChaChaEncryptor::new([0x00; 32]);
            let sender = AccountingSender {
                packet_count: Arc::clone(&packet_count),
                byte_count: Arc::clone(&byte_count),
            };

            let pipeline = FiudpSender::new(reader, fec, encryptor, sender, Duration::from_secs(0), 0, 0, false);
            
            pipeline.send(
                ParityRatio::try_from(pct).unwrap(),
                RendezvousSecs::new(3600),
                SessionId::new(1)
            ).unwrap();

            let final_packets = *packet_count.lock().unwrap();
            let final_bytes = *byte_count.lock().unwrap();
            
            // To compare to standard protocols, remember that UDP has 8 bytes header, IPv4 has 20 bytes header.
            // But this measures the application layer UDP payload (which is exactly 1428 bytes per packet in FIUDP).
            // Total IP footprint = final_bytes + (final_packets * 28)
            let ip_footprint = final_bytes + (final_packets * 28);
            
            let overhead_pct = ((ip_footprint as f64 / size as f64) - 1.0) * 100.0;

            println!(
                "{:>8} B   | {:>8}% | {:>13} | {:>18} B | {:>16.1}%",
                size, pct, final_packets, ip_footprint, overhead_pct
            );
        }
        println!("---------------------------------------------------------------------------------");
    }
    println!();
}
