# attack_generator.py (FIXED — adds Ethernet headers)

from scapy.all import *
import random

def pkt(*layers):
    """Wrap every packet with an Ethernet header so dpkt can parse it"""
    return Ether() / layers[0]


# ─────────────────────────────────────────────────
# 1. NORMAL TRAFFIC
# ─────────────────────────────────────────────────

def gen_normal(output="data/raw/test_normal.pcap", count=200):
    packets = []
    client  = "10.0.0.50"
    servers = ["142.250.190.78", "151.101.1.140", "104.16.132.229"]

    for _ in range(count):
        srv   = random.choice(servers)
        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443, 8080])

        packets.append(pkt(
            IP(src=client, dst=srv) /
            TCP(sport=sport, dport=dport, flags="S",
                window=random.randint(29000, 65535))
        ))
        packets.append(pkt(
            IP(src=srv, dst=client) /
            TCP(sport=dport, dport=sport, flags="SA",
                window=random.randint(29000, 65535))
        ))
        for _ in range(random.randint(3, 15)):
            payload_size = random.randint(100, 1400)
            packets.append(pkt(
                IP(src=srv, dst=client) /
                TCP(sport=dport, dport=sport, flags="PA",
                    window=random.randint(29000, 65535)) /
                Raw(load=b"X" * payload_size)
            ))
        packets.append(pkt(
            IP(src=client, dst=srv) /
            TCP(sport=sport, dport=dport, flags="FA")
        ))

    wrpcap(output, packets)
    print(f"✅ Normal traffic: {len(packets)} packets → {output}")


# ─────────────────────────────────────────────────
# 2. DDoS — SYN FLOOD
# ─────────────────────────────────────────────────

def gen_ddos(output="data/raw/test_ddos.pcap", count=2000):
    packets = []
    target  = "10.0.0.100"

    for _ in range(count):
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        packets.append(pkt(
            IP(src=src_ip, dst=target) /
            TCP(sport=random.randint(1024, 65535),
                dport=80, flags="S", window=1024)
        ))

    wrpcap(output, packets)
    print(f"✅ DDoS SYN flood: {len(packets)} packets → {output}")


# ─────────────────────────────────────────────────
# 3. PORT SCAN
# ─────────────────────────────────────────────────

def gen_portscan(output="data/raw/test_portscan.pcap"):
    packets  = []
    attacker = "10.0.0.77"
    target   = "10.0.0.100"

    ports = list(range(1, 1025))
    random.shuffle(ports)

    for port in ports:
        packets.append(pkt(
            IP(src=attacker, dst=target) /
            TCP(sport=random.randint(40000, 65535),
                dport=port, flags="S", window=1024)
        ))

    wrpcap(output, packets)
    print(f"✅ Port scan: {len(packets)} packets → {output}")


# ─────────────────────────────────────────────────
# 4. BEACONING (Botnet C2)
# ─────────────────────────────────────────────────

def gen_beaconing(output="data/raw/test_beaconing.pcap", beacons=100):
    packets  = []
    infected = "10.0.0.55"
    c2       = "185.220.101.42"

    for i in range(beacons):
        sport = random.randint(49152, 65535)
        beacon_size = random.randint(48, 52)

        packets.append(pkt(
            IP(src=infected, dst=c2) /
            TCP(sport=sport, dport=443, flags="S", window=8192)
        ))
        packets.append(pkt(
            IP(src=c2, dst=infected) /
            TCP(sport=443, dport=sport, flags="SA", window=8192)
        ))
        packets.append(pkt(
            IP(src=infected, dst=c2) /
            TCP(sport=sport, dport=443, flags="PA", window=8192) /
            Raw(load=b"B" * beacon_size)
        ))
        packets.append(pkt(
            IP(src=c2, dst=infected) /
            TCP(sport=443, dport=sport, flags="PA", window=8192) /
            Raw(load=b"R" * random.randint(30, 35))
        ))

    wrpcap(output, packets)
    print(f"✅ Beaconing: {len(packets)} packets → {output}")


# ─────────────────────────────────────────────────
# 5. DATA EXFILTRATION
# ─────────────────────────────────────────────────

def gen_exfiltration(output="data/raw/test_exfiltration.pcap"):
    packets  = []
    insider  = "10.0.0.30"
    external = "45.33.32.156"
    sport    = 51234

    packets.append(pkt(
        IP(src=insider, dst=external) /
        TCP(sport=sport, dport=443, flags="S", window=65535)
    ))
    packets.append(pkt(
        IP(src=external, dst=insider) /
        TCP(sport=443, dport=sport, flags="SA", window=65535)
    ))
    packets.append(pkt(
        IP(src=insider, dst=external) /
        TCP(sport=sport, dport=443, flags="A", window=65535)
    ))

    for _ in range(500):
        packets.append(pkt(
            IP(src=insider, dst=external) /
            TCP(sport=sport, dport=443, flags="PA", window=65535) /
            Raw(load=b"D" * 1400)
        ))

    for _ in range(20):
        packets.append(pkt(
            IP(src=external, dst=insider) /
            TCP(sport=443, dport=sport, flags="A", window=65535)
        ))

    packets.append(pkt(
        IP(src=insider, dst=external) /
        TCP(sport=sport, dport=443, flags="FA", window=65535)
    ))

    wrpcap(output, packets)
    print(f"✅ Exfiltration: {len(packets)} packets → {output}")


# ─────────────────────────────────────────────────

if __name__ == "__main__":
    print("Generating attack test PCAPs...\n")
    gen_normal()
    gen_ddos()
    gen_portscan()
    gen_beaconing()
    gen_exfiltration()
    print("\n🎯 All 5 PCAPs generated in data/raw/")