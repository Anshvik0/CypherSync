# dns_feature_extractor.py
# Reads DNS PCAP → extracts features → saves labeled CSV for Person 2

import dpkt
import socket
import math
import csv
from collections import Counter

# ── FEATURE FUNCTIONS ──────────────────────────────

def entropy(s):
    """
    Shannon entropy of a string.
    High value = random = DGA-like
    Low value  = readable = normal
    """
    s = s.lower().replace(".", "")
    if not s:
        return 0.0
    counts = Counter(s)
    total  = len(s)
    return round(
        -sum((c/total) * math.log2(c/total) for c in counts.values()),
        4
    )

def subdomain_count(domain):
    """
    Count labels in a domain.
    google.com         → 2 (normal)
    mail.google.com    → 3 (normal)
    abc123xyz.evil.com → 3 (normal count but long label)
    dGhpcyBpc.data.c2.com → 4 (tunnel — many labels)
    """
    return len(domain.rstrip(".").split("."))

def assign_label(domain):
    """
    Assign ground truth label based on domain characteristics.
    0 = Normal
    1 = DGA
    2 = DNS Tunnel
    """
    parts      = domain.rstrip(".").split(".")
    first_part = parts[0]  # The leftmost label (most important)

    # Tunnel: very long first label (encoded data stuffed here)
    if len(first_part) > 30:
        return 2

    # DGA: high entropy + long + no vowel pattern
    ent       = entropy(domain)
    vowels    = sum(1 for c in first_part if c in "aeiou")
    vowel_ratio = vowels / len(first_part) if first_part else 0

    if ent > 3.5 and len(first_part) > 10 and vowel_ratio < 0.2:
        return 1

    return 0


# ── MAIN EXTRACTOR ─────────────────────────────────

def extract_dns_features(pcap_file, output_csv):
    """
    Reads DNS PCAP → computes features → saves labeled CSV.
    """
    rows = []

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for timestamp, raw in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(raw)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue

                udp = ip.data
                if udp.dport != 53 and udp.sport != 53:
                    continue

                dns = dpkt.dns.DNS(udp.data)

                # Only look at queries (not responses)
                if dns.qr != dpkt.dns.DNS_Q:
                    continue

                for question in dns.qd:
                    domain = question.name.lower()

                    if not domain:
                        continue

                    parts        = domain.rstrip(".").split(".")
                    first_label  = parts[0]
                    ent          = entropy(domain)
                    sub_count    = subdomain_count(domain)
                    query_len    = len(domain)
                    label        = assign_label(domain)

                    # dns_nxdomain_ratio:
                    # High entropy domains almost always get NXDOMAIN in reality
                    # We simulate this: DGA(1) = high, Tunnel(2) = medium, Normal(0) = low
                    nxdomain_ratio = (
                        0.92 if label == 1 else
                        0.45 if label == 2 else
                        0.02
                    )

                    rows.append({
                        "src_ip":             socket.inet_ntoa(ip.src),
                        "query_name":         domain,
                        "dns_query_length":   query_len,
                        "dns_query_entropy":  ent,
                        "dns_subdomain_count": sub_count,
                        "dns_nxdomain_ratio": nxdomain_ratio,
                        "record_type":        question.type,
                        "label":              label,
                        "label_name": (
                            "normal" if label == 0 else
                            "dga"    if label == 1 else
                            "tunnel"
                        )
                    })

            except Exception:
                continue

    # Save to CSV
    if not rows:
        print("❌ No DNS queries found in PCAP")
        return

    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    # Summary
    labels = [r["label_name"] for r in rows]
    normal = labels.count("normal")
    dga    = labels.count("dga")
    tunnel = labels.count("tunnel")

    print(f"\n✅ CSV saved to: {output_csv}")
    print(f"   Total rows : {len(rows)}")
    print(f"   Normal     : {normal}")
    print(f"   DGA        : {dga}")
    print(f"   Tunnel     : {tunnel}")


# ── RUN ────────────────────────────────────────────

if __name__ == "__main__":
    extract_dns_features(
        pcap_file  = "data/raw/dns_synthetic.pcap",
        output_csv = "data/processed/dns_features.csv"
    )