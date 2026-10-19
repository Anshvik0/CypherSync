# tls_csv_generator.py
# Generates synthetic TLS metadata features for malware detection
# Label 0 = Normal TLS, Label 1 = TLS Malware (C2)

import csv
import random
import hashlib

# ── KNOWN NORMAL JA3 HASHES ──────────────────────
# Real JA3 hashes from common browsers
NORMAL_JA3 = [
    "aaa9d4873f7f8c4f3fce4bd23f9c7d0d",  # Chrome
    "579ccef312d18482fc42e2b822ca2430",  # Firefox
    "b32309a26951912be7dba376398abc3b",  # Safari
    "c35dabdd40e08dc1ad5c3e3e55e3f5a3",  # Edge
    "d7b0b55c2b7349b36f8a60e34ede9fec",  # curl
    "5b4fd62a47c0f7b42db7f35f9c27e2f6",  # Python requests
    "9e10692f1b7f78228b2d4e424db3a98c",  # wget
    "c86c1a48e4a6acb28cf8c12c61c54c33",  # Opera
]

# ── MALWARE JA3 HASHES ────────────────────────────
# Simulated unknown/custom TLS library fingerprints
def make_malware_ja3():
    """Generate a random JA3 hash — simulates unknown malware TLS library"""
    random_string = str(random.random())
    return hashlib.md5(random_string.encode()).hexdigest()

# ── KNOWN MALICIOUS JA3 HASHES ────────────────────
# Real known-bad JA3 hashes (from threat intel)
KNOWN_BAD_JA3 = [
    "a0e9f5d64349fb13191bc781f81f42e1",  # Metasploit
    "6734f37431670b3ab4292b8f60f29984",  # Cobalt Strike
    "72a589da586844d7f0818ce684948eea",  # TrickBot
    "b742b407d1d3a3f03fde73d1b563041a",  # Dridex
    "eb88d0b3978e1bcfa728e2f6f36f6c1b",  # Emotet
]


# ── GENERATE ROWS ─────────────────────────────────

def generate_tls_csv(output_csv="data/processed/tls_features.csv",
                     count_each=400):

    rows = []

    # ── Normal TLS ────────────────────────────────
    print(f"Generating {count_each} normal TLS samples...")
    for _ in range(count_each):
        rows.append({
            # Known browser/app JA3 hash
            "ja3_hash":        random.choice(NORMAL_JA3),

            # Browsers ALWAYS send SNI (server name)
            "sni_present":     1,

            # Normal traffic has highly variable packet sizes
            # (HTML pages, images, JS files — all different sizes)
            "tls_pkt_size_std": round(random.uniform(150, 400), 2),

            # Moderate packet rate — human browsing pace
            "packet_rate":     round(random.uniform(5, 50), 2),

            # Short to medium sessions (browsing a page)
            "flow_duration":   round(random.uniform(1, 120), 2),

            # Upload << Download for normal browsing
            "bytes_per_sec":   round(random.uniform(500, 50000), 2),

            "label":           0,
            "label_name":      "normal"
        })

    # ── TLS Malware (C2 beaconing) ────────────────
    print(f"Generating {count_each} TLS malware samples...")
    for _ in range(count_each):
        # Mix of known-bad JA3 and random unknown ones
        if random.random() < 0.4:
            ja3 = random.choice(KNOWN_BAD_JA3)
        else:
            ja3 = make_malware_ja3()

        rows.append({
            "ja3_hash": ja3,

            # Malware often skips SNI or uses fake one
            "sni_present": random.choice([0, 0, 0, 1]),  # mostly absent

            # C2 beacons send FIXED size encrypted commands
            # Very LOW std deviation — almost same size every time
            "tls_pkt_size_std": round(random.uniform(2, 30), 2),

            # Very regular, periodic rate (beaconing)
            "packet_rate":     round(random.uniform(0.5, 3), 2),

            # Very LONG sessions — persistent C2 channel stays open
            "flow_duration":   round(random.uniform(300, 7200), 2),

            # Low bytes — small encrypted commands only
            "bytes_per_sec":   round(random.uniform(10, 500), 2),

            "label":      1,
            "label_name": "malware"
        })

    # Shuffle
    random.shuffle(rows)

    # Save CSV
    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    # Summary
    print(f"\n✅ CSV saved: {output_csv}")
    print(f"   Total rows : {len(rows)}")
    print(f"   Normal     : {count_each}")
    print(f"   Malware    : {count_each}")
    print(f"\nSample rows:")
    for row in rows[:4]:
        print(
            f"  {row['label_name']:8} | "
            f"sni={row['sni_present']} | "
            f"pkt_std={row['tls_pkt_size_std']:6} | "
            f"duration={row['flow_duration']:7}s | "
            f"ja3={row['ja3_hash'][:16]}..."
        )


if __name__ == "__main__":
    generate_tls_csv()