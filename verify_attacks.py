# verify_attacks.py
# Run parser on all 5 test PCAPs and check if features make sense

import json
from pcap_parser import parse_pcap

test_files = [
    ("NORMAL",        "data/raw/test_normal.pcap"),
    ("DDoS",          "data/raw/test_ddos.pcap"),
    ("PORT SCAN",     "data/raw/test_portscan.pcap"),
    ("BEACONING",     "data/raw/test_beaconing.pcap"),
    ("EXFILTRATION",  "data/raw/test_exfiltration.pcap"),
]

for label, path in test_files:
    print(f"\n{'='*50}")
    print(f"  {label} — {path}")
    print(f"{'='*50}")

    flows = parse_pcap(path)
    print(f"  Flows found: {len(flows)}")

    if flows:
        # Show first flow's key features
        f = flows[0]["ml_features"]
        print(f"  Flow Bytes/s:                {f['Flow Bytes/s']}")
        print(f"  Fwd Packets:                 {f['Subflow Fwd Packets']}")
        print(f"  Total Fwd Bytes:             {f['Total Length of Fwd Packets']}")
        print(f"  Total Bwd Bytes:             {f['Total Length of Bwd Packets']}")
        print(f"  Down/Up Ratio:               {f['Down/Up Ratio']}")
        print(f"  ACK Flag Count:              {f['ACK Flag Count']}")
        print(f"  Packet Length Std:            {f['Packet Length Std']}")
        print(f"  Flow IAT Mean:               {f['Flow IAT Mean']}")

print(f"\n{'='*50}")
print("DONE ✅")