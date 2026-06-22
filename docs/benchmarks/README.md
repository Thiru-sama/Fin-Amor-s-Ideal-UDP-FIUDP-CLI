# FIUDP Benchmarks & Performance Metrics

This directory contains the reproducible benchmarks and academic performance plots for the FIUDP protocol, specifically targeting e-ink IoT displays (like the TRMNL).

## 1. Network Footprint (Overhead)
This stacked bar chart breaks down exactly where bytes are spent over the air. While FIUDP with 10% FEC uses slightly more total bandwidth than HTTPS for a 48KB payload, it trades this for zero connection overhead.

![Network Footprint](./academic_footprint_stacked.png)

## 2. Establishment Latency (Zero-RTT)
The primary advantage of FIUDP for battery-powered IoT devices is the elimination of Round-Trip Times (RTT). The Wi-Fi radio only wakes up to transmit (or receive) the payload burst, drastically reducing active time compared to TCP/TLS handshakes.

![RTT Latency](./academic_rtt_latency.png)

## 3. Server Processing Time
The processing time added by ChaCha20 encryption and Reed-Solomon Forward Error Correction (FEC) is negligible on the server side (less than 400 µs for a 48KB frame).

![Processing Time](./academic_processing_time.png)

## Reproducing the Plots
You can regenerate these high-resolution plots by running the included Python script from the root directory:

```bash
python -m venv .venv
source .venv/bin/activate
pip install matplotlib seaborn pandas
python scripts/plot_metrics.py
```
