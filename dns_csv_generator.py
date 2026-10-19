# dns_csv_generator.py
# Generates DNS features CSV directly — no PCAP parsing needed
# Cleaner approach for synthetic labeled data

import csv
import math
import random
import string
from collections import Counter

# ── FEATURE FUNCTIONS ──────────────────────────────

def entropy(s):
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
    return len(domain.rstrip(".").split("."))

# ── DOMAIN GENERATORS ──────────────────────────────

NORMAL_DOMAINS = [
    "google.com", "youtube.com", "facebook.com",
    "instagram.com", "amazon.com", "netflix.com",
    "microsoft.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "twitter.com", "linkedin.com",
    "apple.com", "reddit.com", "whatsapp.com",
    "mail.google.com", "drive.google.com",
    "api.github.com", "cdn.amazon.com",
    "maps.google.com", "news.bbc.com", "login.yahoo.com"
]

def make_dga_domain():
    length = random.randint(12, 20)
    chars  = string.ascii_lowercase + string.digits
    name   = ''.join(random.choices(chars, k=length))
    tld    = random.choice([".com", ".net", ".org", ".xyz", ".top"])
    return name + tld

def make_tunnel_domain():
    data_chunk  = ''.join(random.choices(
        string.ascii_letters + string.digits, k=random.randint(35, 50)
    ))
    base_domain = random.choice(["evil-c2.com", "tunnel.net", "data-out.org"])
    return f"{data_chunk}.{base_domain}"

# ── MAIN GENERATOR ─────────────────────────────────

def generate_dns_csv(output_csv="data/processed/dns_features.csv",
                     count_each=300):

    rows = []

    # ── Normal DNS ────────────────────────────────
    print(f"Generating {count_each} normal samples...")
    for _ in range(count_each):
        domain = random.choice(NORMAL_DOMAINS)
        rows.append({
            "query_name":            domain,
            "dns_query_length":      len(domain),
            "dns_query_entropy":     entropy(domain),
            "dns_subdomain_count":   subdomain_count(domain),
            "dns_nxdomain_ratio":    round(random.uniform(0.0, 0.05), 3),
            "label":                 0,
            "label_name":            "normal"
        })

    # ── DGA ───────────────────────────────────────
    print(f"Generating {count_each} DGA samples...")
    for _ in range(count_each):
        domain = make_dga_domain()
        rows.append({
            "query_name":            domain,
            "dns_query_length":      len(domain),
            "dns_query_entropy":     entropy(domain),
            "dns_subdomain_count":   subdomain_count(domain),
            "dns_nxdomain_ratio":    round(random.uniform(0.80, 0.98), 3),
            "label":                 1,
            "label_name":            "dga"
        })

    # ── DNS Tunnel ────────────────────────────────
    print(f"Generating {count_each} DNS tunnel samples...")
    for _ in range(count_each):
        domain = make_tunnel_domain()
        rows.append({
            "query_name":            domain,
            "dns_query_length":      len(domain),
            "dns_query_entropy":     entropy(domain),
            "dns_subdomain_count":   subdomain_count(domain),
            "dns_nxdomain_ratio":    round(random.uniform(0.30, 0.55), 3),
            "label":                 2,
            "label_name":            "tunnel"
        })

    # Shuffle rows
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
    print(f"   DGA        : {count_each}")
    print(f"   Tunnel     : {count_each}")
    print(f"\nSample rows:")
    for row in rows[:3]:
        print(f"  {row['label_name']:8} | entropy={row['dns_query_entropy']} "
              f"| len={row['dns_query_length']} "
              f"| {row['query_name'][:40]}")


if __name__ == "__main__":
    generate_dns_csv()