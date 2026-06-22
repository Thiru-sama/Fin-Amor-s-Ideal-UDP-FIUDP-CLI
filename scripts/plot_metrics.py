import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Set the style for high-end academic-looking plots
sns.set_theme(style="white", context="paper", font_scale=1.3)
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Inter', 'Roboto', 'Arial', 'sans-serif']
plt.rcParams['axes.linewidth'] = 1.2
plt.rcParams['axes.edgecolor'] = '#333333'

output_dir = os.path.join(os.path.dirname(__file__), "..", "docs", "benchmarks")
os.makedirs(output_dir, exist_ok=True)

def plot_stacked_footprint():
    """Stacked bar chart showing exactly WHERE the bytes are spent."""
    labels = ['HTTPS\n(TLS 1.3)', 'MQTT\n(QoS 0)', 'FIUDP\n(0% FEC)', 'FIUDP\n(10% FEC)']
    
    # Components of the transmission for a 48KB Payload
    payload = np.array([48000, 48000, 48000, 48000])
    parity_fec = np.array([0, 0, 0, 4800 * 1.01])  # Approx 4.8KB for 10%
    handshakes = np.array([1680, 194, 0, 0])       # TLS/TCP vs MQTT Connect vs Zero
    headers_overhead = np.array([2690, 806, 980, 1092]) # Per-packet headers (IP/TCP/UDP/TLS/Poly1305)
    
    fig, ax = plt.subplots(figsize=(10, 6.5))
    
    width = 0.6
    
    # Colors optimized for colorblindness and print
    c_payload = '#bdc3c7'
    c_handshake = '#e74c3c'
    c_headers = '#f39c12'
    c_fec = '#27ae60'
    
    p1 = ax.bar(labels, payload, width, label='Payload Utile (48 Ko)', color=c_payload, edgecolor='black', linewidth=0.5)
    p2 = ax.bar(labels, handshakes, width, bottom=payload, label='Overhead de Connexion (Handshakes)', color=c_handshake, edgecolor='black', linewidth=0.5)
    p3 = ax.bar(labels, headers_overhead, width, bottom=payload+handshakes, label='Overhead d\'En-têtes (IP/TCP/UDP/Crypto)', color=c_headers, edgecolor='black', linewidth=0.5)
    p4 = ax.bar(labels, parity_fec, width, bottom=payload+handshakes+headers_overhead, label='Redondance FEC (Reed-Solomon)', color=c_fec, edgecolor='black', linewidth=0.5)
    
    # Add total byte annotations
    totals = payload + handshakes + headers_overhead + parity_fec
    for i, total in enumerate(totals):
        ax.text(i, total + 1000, f"{int(total):,} B", ha='center', va='bottom', fontweight='bold', fontsize=12)

    ax.set_ylabel('Volume de Données Transmis (Octets)', fontweight='bold')
    ax.set_title("Décomposition de l'Empreinte Réseau (Payload 48 Ko)", pad=20, fontweight='bold', fontsize=16)
    
    # Move legend outside
    ax.legend(loc='upper left', bbox_to_anchor=(1, 1), frameon=False)
    
    sns.despine(top=True, right=True)
    ax.yaxis.grid(True, linestyle='--', alpha=0.6)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "academic_footprint_stacked.png"), dpi=300, bbox_inches='tight')
    plt.close()
    print("Saved academic_footprint_stacked.png")

def plot_rtt_latency():
    """A visualization of the Zero-RTT advantage."""
    protocols = ['FIUDP\n(Zero-RTT)', 'MQTT\n(TCP)', 'HTTPS\n(TLS 1.3)']
    rtt_counts = [0, 2, 4]  # FIUDP=0, MQTT=TCP+Conn, HTTPS=TCP+TLS1+TLS2+HTTP
    
    fig, ax = plt.subplots(figsize=(8, 5))
    
    colors = ['#27ae60', '#e67e22', '#c0392b']
    
    bars = ax.bar(protocols, rtt_counts, color=colors, width=0.65, edgecolor='black', linewidth=1)
    
    # Annotate with the impact on the radio
    impact_texts = [
        "Radio\néveillée\npour Tx",
        "Radio éveillée\n(2 RTTs + Tx)",
        "Radio éveillée\n(4 RTTs + Tx)"
    ]
    
    for bar, text in zip(bars, impact_texts):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.15, str(int(height)) + " Allers-Retours", 
                ha='center', va='bottom', fontweight='bold', fontsize=12)
        
        if height == 0:
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.6, text, 
                    ha='center', va='bottom', color='black', 
                    fontweight='bold', fontsize=11)
        else:
            ax.text(bar.get_x() + bar.get_width()/2., height / 2, text, 
                    ha='center', va='center', color='white', 
                    fontweight='bold', fontsize=11)

    ax.set_ylim(0, 5)
    ax.set_yticks(range(6))
    ax.set_ylabel('Nombre d\'Allers-Retours Réseau (RTT)', fontweight='bold')
    ax.set_title("Latence d'Établissement & Coût Énergétique Radio", pad=20, fontweight='bold', fontsize=16)
    
    sns.despine(top=True, right=True, left=True)
    ax.yaxis.grid(True, linestyle='-', alpha=0.2)
    ax.tick_params(axis='y', length=0)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "academic_rtt_latency.png"), dpi=300, bbox_inches='tight')
    plt.close()
    print("Saved academic_rtt_latency.png")

def plot_processing_time():
    """Processing time in microseconds (easier to grasp than MiB/s for IoT)."""
    # 48KB frame processing times derived from criterion data
    data = [
        {"Opération": "Chiffrement ChaCha20", "Temps (µs)": 75},
        {"Opération": "FEC Encodage (10%)", "Temps (µs)": 169},
        {"Opération": "Pipeline Complet (Tx)", "Temps (µs)": 338},
    ]
    df = pd.DataFrame(data)
    
    fig, ax = plt.subplots(figsize=(9, 4))
    
    colors = sns.color_palette("Blues_d", len(df))
    sns.barplot(data=df, y="Opération", x="Temps (µs)", palette=colors, ax=ax, orient='h', edgecolor='black', linewidth=0.5)
    
    for p in ax.patches:
        width = p.get_width()
        ax.annotate(f'{int(width)} µs', 
                    (width, p.get_y() + p.get_height() / 2.), 
                    ha='left', va='center', 
                    fontsize=12, fontweight='bold', color='black', xytext=(8, 0), 
                    textcoords='offset points')

    ax.set_xlim(0, 450)
    ax.set_title("Temps de Traitement Serveur par Image (48 Ko)", pad=20, fontweight='bold', fontsize=16)
    ax.set_xlabel("Temps d'exécution (Microsecondes)", fontweight='bold')
    ax.set_ylabel("")
    
    sns.despine(bottom=True, left=True)
    ax.xaxis.grid(True, linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "academic_processing_time.png"), dpi=300, bbox_inches='tight')
    plt.close()
    print("Saved academic_processing_time.png")

if __name__ == "__main__":
    plot_stacked_footprint()
    plot_rtt_latency()
    plot_processing_time()
