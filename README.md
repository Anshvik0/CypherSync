# CypherSync
AI-Based Cyber Threat Detection System for critical infrastructure networks
An AI-powered cybersecurity system designed to detect threats in 
unidirectional (one-way) IP traffic — the kind used in critical 
infrastructure like nuclear facilities, power grids, and defense 
networks where traditional security tools fail.

Built as part of **Smart India Hackathon 2026** in a team of 6.

---

## My Role — Network Traffic Analyst & Protocol Engineer

I built the core network packet parsing and feature extraction 
engine for this system.

### Key Contributions

- Built a standalone PCAP parser (`pcap_parser.py`) in Python 
  using `dpkt` that reconstructs network sessions from raw binary 
  packet captures and extracts 28 directional statistical features 
  aligned with the CIC-IDS-2017 research benchmark

- Implemented protocol-aware flow classification that automatically 
  routes traffic to 3 specialized AI models:
  - General threats (DDoS, Port Scan, Botnet, Exfiltration)
  - DNS threats (DGA/Tunneling)
  - TLS threats (encrypted malware)
  using Shannon entropy and JA3 fingerprinting

- Designed and tested a dynamic flow aggregation engine to handle 
  high-volume SYN flood attacks and improve ML model detection 
  accuracy

- Generated synthetic labeled datasets (900-row DNS, 800-row TLS) 
  and 5 realistic attack PCAP files for team-wide ML training and 
  integration testing

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Python | Core development language |
| dpkt | Raw PCAP packet parsing |
| Scapy | Network packet crafting and analysis |
| NumPy | Statistical feature extraction |
| FastAPI | REST API endpoints |
| Pydantic | Data validation |

---

## System Architecture

Raw PCAP Files
↓
PCAP Parser (pcap_parser.py)
↓
Feature Extraction (28 features)
↓
Protocol-Aware Flow Classifier
↓
┌─────────────┬──────────────┬─────────────┐
│ General │ DNS Threat │ TLS Threat │
│ Threat Model│ Model │ Model │
│ (DDoS/Scan/ │ (DGA/ │ (Encrypted │
│ Botnet) │ Tunneling) │ Malware) │
└─────────────┴──────────────┴─────────────┘


---

## About the Problem

Traditional security tools fail on unidirectional traffic because 
they rely on bidirectional communication patterns. CypherSync 
solves this by extracting directional statistical features from 
one-way packet flows — making it viable for air-gapped and 
critical infrastructure networks.

---

## Status

🚧 Active development — core packet parsing engine complete, 
ML model integration in progress.

---

## Author

**Anshvik Pal**
B.Tech CSE, Manipal University Jaipur
[LinkedIn](https://www.linkedin.com/in/anshvik-pal-906549371/)
