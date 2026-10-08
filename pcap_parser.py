# pcap_parser.py
import dpkt
import socket
import math
import numpy as np
from collections import Counter, defaultdict


class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.src_port  = src_port
        self.dst_port  = dst_port
        self.protocol  = protocol

        self.packet_count = 0
        self.byte_count   = 0
        self.start_time   = None
        self.end_time     = None
        self.last_time    = None

        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0

        self.init_win_fwd = -1
        self.init_win_bwd = -1

        self.packet_sizes        = []
        self.inter_arrival_times = []

        self.initiator_ip   = src_ip
        self.initiator_port = src_port
        self.fwd_packet_count = 0
        self.bwd_packet_count = 0
        self.fwd_bytes        = 0
        self.bwd_bytes        = 0
        self.fwd_packet_sizes = []
        self.bwd_packet_sizes = []
        self.fwd_iats         = []
        self.last_fwd_time    = None

        self.dns_queries = []
        self.dns_response_codes = []

        self.tls_ja3_hash    = None
        self.tls_sni         = None
        self.tls_sni_present = False

    def _is_fwd(self, src_ip, src_port):
        return src_ip == self.initiator_ip and src_port == self.initiator_port

    def add_packet(self, timestamp, size, flags, src_ip, src_port, win_size=0):
        if self.start_time is None:
            self.start_time = timestamp
        self.end_time = timestamp

        if self.last_time is not None:
            self.inter_arrival_times.append(timestamp - self.last_time)
        self.last_time = timestamp

        self.packet_count += 1
        self.byte_count   += size
        self.packet_sizes.append(size)

        if self.protocol == 6:
            if flags & 0x02: self.syn_count += 1
            if flags & 0x10: self.ack_count += 1
            if flags & 0x01: self.fin_count += 1
            if flags & 0x04: self.rst_count += 1
            if flags & 0x08: self.psh_count += 1

        is_fwd = self._is_fwd(src_ip, src_port)
        if is_fwd:
            self.fwd_packet_count += 1
            self.fwd_bytes        += size
            self.fwd_packet_sizes.append(size)
            if self.init_win_fwd == -1:
                self.init_win_fwd = win_size
            if self.last_fwd_time is not None:
                self.fwd_iats.append(timestamp - self.last_fwd_time)
            self.last_fwd_time = timestamp
        else:
            self.bwd_packet_count += 1
            self.bwd_bytes        += size
            self.bwd_packet_sizes.append(size)
            if self.init_win_bwd == -1:
                self.init_win_bwd = win_size

    def add_dns_query(self, qname, rcode=None):
        self.dns_queries.append(qname)
        if rcode is not None:
            self.dns_response_codes.append(rcode)

    def add_tls_info(self, ja3_hash=None, sni=None):
        if ja3_hash:
            self.tls_ja3_hash = ja3_hash
        if sni:
            self.tls_sni = sni
            self.tls_sni_present = True

    def duration(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    def get_flow_type(self):
        if self.src_port == 53 or self.dst_port == 53:
            return "dns"
        if self.dst_port == 443 or self.src_port == 443:
            return "tls"
        return "general"


class FlowTracker:
    def __init__(self):
        self.flows = {}

    def _key(self, src_ip, dst_ip, src_port, dst_port, proto):
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a > b:
            a, b = b, a
        return (a, b, proto)

    def process_packet(self, ts, src_ip, dst_ip,
                       src_port, dst_port, proto, size,
                       flags=0, win_size=0):
        key = self._key(src_ip, dst_ip, src_port, dst_port, proto)
        if key not in self.flows:
            self.flows[key] = Flow(src_ip, dst_ip, src_port, dst_port, proto)
        self.flows[key].add_packet(ts, size, flags, src_ip, src_port, win_size)
        return key

    def get_flow(self, key):
        return self.flows.get(key)

    def get_flows(self):
        return list(self.flows.values())


# ─────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────

def _entropy(s):
    s = s.lower().replace(".", "")
    if not s:
        return 0.0
    counts = Counter(s)
    total  = len(s)
    return round(-sum((c/total) * math.log2(c/total) for c in counts.values()), 4)

def _subdomain_count(domain):
    return len(domain.rstrip(".").split("."))

def _safe(func, data, default=0):
    if not data: return default
    return round(float(func(data)), 4)

def _build_traffic_dict(flow, dur):
    avg_pkt_size = round(flow.byte_count / flow.packet_count, 2) if flow.packet_count > 0 else 0.0
    pkt_rate = round(flow.packet_count / dur, 2)
    return {
        "packet_count":        flow.packet_count,
        "total_bytes":         flow.byte_count,
        "average_packet_size": avg_pkt_size,
        "duration_seconds":    round(dur, 2),
        "packet_rate":         pkt_rate
    }


# ─────────────────────────────────────────────────
# JA3 HASH COMPUTATION
# ─────────────────────────────────────────────────

def _compute_ja3(tcp_data):
    try:
        if len(tcp_data) < 6: return None, None
        if tcp_data[0] != 22 or tcp_data[5] != 1: return None, None
        if len(tcp_data) < 44: return None, None

        tls_version = (tcp_data[9] << 8) | tcp_data[10]
        pos = 43
        if pos >= len(tcp_data): return None, None
        session_id_len = tcp_data[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(tcp_data): return None, None
        cipher_len = (tcp_data[pos] << 8) | tcp_data[pos+1]
        pos += 2
        ciphers = []
        for i in range(0, cipher_len, 2):
            if pos + i + 1 < len(tcp_data):
                c = (tcp_data[pos+i] << 8) | tcp_data[pos+i+1]
                if (c & 0x0f0f) != 0x0a0a:
                    ciphers.append(str(c))
        pos += cipher_len

        if pos >= len(tcp_data): return None, None
        comp_len = tcp_data[pos]
        pos += 1 + comp_len

        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        sni = None

        if pos + 2 <= len(tcp_data):
            ext_total_len = (tcp_data[pos] << 8) | tcp_data[pos+1]
            pos += 2
            ext_end = pos + ext_total_len

            while pos + 4 <= ext_end and pos + 4 <= len(tcp_data):
                ext_type = (tcp_data[pos] << 8) | tcp_data[pos+1]
                ext_len  = (tcp_data[pos+2] << 8) | tcp_data[pos+3]
                pos += 4

                if (ext_type & 0x0f0f) != 0x0a0a:
                    extensions.append(str(ext_type))

                if ext_type == 0 and ext_len > 5:
                    try:
                        name_len = (tcp_data[pos+3] << 8) | tcp_data[pos+4]
                        sni = tcp_data[pos+5:pos+5+name_len].decode('ascii', errors='ignore')
                    except Exception:
                        pass

                if ext_type == 10 and ext_len > 2:
                    curves_len = (tcp_data[pos] << 8) | tcp_data[pos+1]
                    for i in range(2, 2 + curves_len, 2):
                        if pos + i + 1 < len(tcp_data):
                            curve = (tcp_data[pos+i] << 8) | tcp_data[pos+i+1]
                            if (curve & 0x0f0f) != 0x0a0a:
                                elliptic_curves.append(str(curve))

                if ext_type == 11 and ext_len > 1:
                    fmt_len = tcp_data[pos]
                    for i in range(1, 1 + fmt_len):
                        if pos + i < len(tcp_data):
                            ec_point_formats.append(str(tcp_data[pos+i]))

                pos += ext_len

        ja3_str = ",".join([
            str(tls_version),
            "-".join(ciphers),
            "-".join(extensions),
            "-".join(elliptic_curves),
            "-".join(ec_point_formats)
        ])
        import hashlib
        return hashlib.md5(ja3_str.encode()).hexdigest(), sni
    except Exception:
        return None, None


# ─────────────────────────────────────────────────
# FEATURE EXTRACTORS
# ─────────────────────────────────────────────────

def _extract_general(flow, index):
    dur = max(flow.duration(), 0.001)
    sizes = flow.packet_sizes
    iats  = flow.inter_arrival_times
    fwd_sizes = flow.fwd_packet_sizes
    bwd_sizes = flow.bwd_packet_sizes

    return {
        "flow": {
            "flow_id":          f"FLOW-{index:03d}",
            "source_ip":        flow.src_ip,
            "destination_ip":   flow.dst_ip,
            "source_port":      flow.src_port,
            "destination_port": flow.dst_port,
            "protocol":         "TCP" if flow.protocol == 6 else "UDP"
        },
        "traffic": _build_traffic_dict(flow, dur),
        "flow_type": "general",
        "ml_features": {
            "Destination Port":              flow.dst_port,
            "Flow Duration":                 round(dur * 1e6, 0),
            "Flow Bytes/s":                  round(flow.byte_count / dur, 4),
            "Average Packet Size":           round(flow.byte_count / flow.packet_count, 4) if flow.packet_count > 0 else 0,
            "Max Packet Length":             max(sizes) if sizes else 0,
            "Packet Length Mean":            _safe(np.mean, sizes),
            "Packet Length Std":             _safe(np.std, sizes),
            "Packet Length Variance":        _safe(np.var, sizes),
            "Flow IAT Mean":                _safe(np.mean, iats),
            "Flow IAT Std":                 _safe(np.std, iats),
            "Flow IAT Max":                 max(iats) if iats else 0,
            "ACK Flag Count":               flow.ack_count,
            "PSH Flag Count":               flow.psh_count,
            "Init_Win_bytes_forward":        flow.init_win_fwd if flow.init_win_fwd != -1 else 0,
            "Init_Win_bytes_backward":       flow.init_win_bwd if flow.init_win_bwd != -1 else 0,
            "Total Length of Fwd Packets":   flow.fwd_bytes,
            "Total Length of Bwd Packets":   flow.bwd_bytes,
            "Fwd Packet Length Mean":        _safe(np.mean, fwd_sizes),
            "Fwd Packet Length Max":         max(fwd_sizes) if fwd_sizes else 0,
            "Bwd Packet Length Max":         max(bwd_sizes) if bwd_sizes else 0,
            "Bwd Packet Length Mean":        _safe(np.mean, bwd_sizes),
            "Bwd Packet Length Std":         _safe(np.std, bwd_sizes),
            "Bwd Packets/s":                round(flow.bwd_packet_count / dur, 4),
            "Down/Up Ratio":                round(flow.bwd_bytes / flow.fwd_bytes, 4) if flow.fwd_bytes > 0 else 0,
            "Subflow Fwd Bytes":            flow.fwd_bytes,
            "Subflow Bwd Bytes":            flow.bwd_bytes,
            "Subflow Fwd Packets":          flow.fwd_packet_count,
            "Fwd IAT Total":               round(sum(flow.fwd_iats), 6) if flow.fwd_iats else 0,
        }
    }


def _extract_dns(flow, index):
    dur = max(flow.duration(), 0.001)
    queries = flow.dns_queries
    if queries:
        avg_entropy    = round(sum(_entropy(q) for q in queries) / len(queries), 4)
        avg_length     = round(sum(len(q) for q in queries) / len(queries), 4)
        avg_subdomains = round(sum(_subdomain_count(q) for q in queries) / len(queries), 4)
    else:
        avg_entropy = avg_length = avg_subdomains = 0

    rcodes = flow.dns_response_codes
    nxdomain_ratio = round(rcodes.count(3) / len(rcodes), 4) if rcodes else 0

    return {
        "flow": {
            "flow_id":          f"FLOW-{index:03d}",
            "source_ip":        flow.src_ip,
            "destination_ip":   flow.dst_ip,
            "source_port":      flow.src_port,
            "destination_port": flow.dst_port,
            "protocol":         "UDP"
        },
        "traffic": _build_traffic_dict(flow, dur),
        "flow_type": "dns",
        "ml_features": {
            "dns_query_entropy":     avg_entropy,
            "dns_query_length":      avg_length,
            "dns_subdomain_count":   avg_subdomains,
            "dns_nxdomain_ratio":    nxdomain_ratio,
        },
        "dns_queries": queries[:5]
    }


def _extract_tls(flow, index):
    dur = max(flow.duration(), 0.001)
    return {
        "flow": {
            "flow_id":          f"FLOW-{index:03d}",
            "source_ip":        flow.src_ip,
            "destination_ip":   flow.dst_ip,
            "source_port":      flow.src_port,
            "destination_port": flow.dst_port,
            "protocol":         "TCP"
        },
        "traffic": _build_traffic_dict(flow, dur),
        "flow_type": "tls",
        "ml_features": {
            "ja3_hash":          flow.tls_ja3_hash or "unknown",
            "sni_present":       1 if flow.tls_sni_present else 0,
            "tls_pkt_size_std":  _safe(np.std, flow.packet_sizes),
            "packet_rate":       round(flow.packet_count / dur, 4),
            "flow_duration":     round(dur, 4),
            "bytes_per_sec":     round(flow.byte_count / dur, 4),
        },
        "tls_sni": flow.tls_sni
    }


# ─────────────────────────────────────────────────
# FLOW AGGREGATION (for DDoS detection)
# ─────────────────────────────────────────────────

def _aggregate_flows(flows, time_window=2.0, min_flows=10):
    """
    Merge multiple single-packet flows targeting the same
    (dst_ip, dst_port) within a time window into one aggregated flow.
    Normal traffic with fewer than min_flows is untouched.
    """
    groups = defaultdict(list)
    for flow in flows:
        key = (flow.dst_ip, flow.dst_port)
        groups[key].append(flow)

    result = []

    for key, group in groups.items():
        if len(group) < min_flows:
            result.extend(group)
            continue

        group.sort(key=lambda f: f.start_time if f.start_time else 0)
        current_window = [group[0]]

        for flow in group[1:]:
            time_diff = (flow.start_time or 0) - (current_window[0].start_time or 0)

            if time_diff <= time_window:
                current_window.append(flow)
            else:
                if len(current_window) >= min_flows:
                    result.append(_merge_flows(current_window, key))
                else:
                    result.extend(current_window)
                current_window = [flow]

        if len(current_window) >= min_flows:
            result.append(_merge_flows(current_window, key))
        else:
            result.extend(current_window)

    return result


def _merge_flows(flows_to_merge, dst_key):
    """Merge multiple flows into one aggregated flow."""
    dst_ip, dst_port = dst_key
    src_ip   = flows_to_merge[0].src_ip
    src_port = flows_to_merge[0].src_port
    protocol = flows_to_merge[0].protocol

    merged = Flow(src_ip, dst_ip, src_port, dst_port, protocol)

    all_start_times = []
    all_end_times   = []

    for f in flows_to_merge:
        merged.packet_count += f.packet_count
        merged.byte_count   += f.byte_count
        merged.syn_count    += f.syn_count
        merged.ack_count    += f.ack_count
        merged.fin_count    += f.fin_count
        merged.rst_count    += f.rst_count
        merged.psh_count    += f.psh_count
        merged.fwd_packet_count += f.fwd_packet_count
        merged.bwd_packet_count += f.bwd_packet_count
        merged.fwd_bytes        += f.fwd_bytes
        merged.bwd_bytes        += f.bwd_bytes
        merged.packet_sizes.extend(f.packet_sizes)
        merged.fwd_packet_sizes.extend(f.fwd_packet_sizes)
        merged.bwd_packet_sizes.extend(f.bwd_packet_sizes)

        if f.start_time: all_start_times.append(f.start_time)
        if f.end_time:   all_end_times.append(f.end_time)

        if merged.init_win_fwd == -1 and f.init_win_fwd != -1:
            merged.init_win_fwd = f.init_win_fwd
        if merged.init_win_bwd == -1 and f.init_win_bwd != -1:
            merged.init_win_bwd = f.init_win_bwd

    if all_start_times:
        merged.start_time = min(all_start_times)
    if all_end_times:
        merged.end_time = max(all_end_times)

    all_start_times.sort()
    for i in range(1, len(all_start_times)):
        iat = all_start_times[i] - all_start_times[i-1]
        merged.inter_arrival_times.append(iat)
        merged.fwd_iats.append(iat)

    return merged


# ─────────────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────────────

def parse_pcap(pcap_file: str) -> list:
    """
    Supports both Ethernet-framed and Raw IP PCAPs automatically.
    Aggregates attack flows targeting the same destination.
    """
    tracker = FlowTracker()

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        link_type = pcap.datalink()

        for timestamp, raw in pcap:
            try:
                ip = None

                try:
                    eth = dpkt.ethernet.Ethernet(raw)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                except Exception:
                    pass

                if ip is None:
                    try:
                        ip = dpkt.ip.IP(raw)
                        if ip.v != 4:
                            continue
                    except Exception:
                        continue

                if ip is None:
                    continue

                src_ip   = socket.inet_ntoa(ip.src)
                dst_ip   = socket.inet_ntoa(ip.dst)
                proto    = ip.p
                size     = len(raw)
                src_port = dst_port = flags = win_size = 0

                if proto == 6 and isinstance(ip.data, dpkt.tcp.TCP):
                    tcp      = ip.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    flags    = tcp.flags
                    win_size = tcp.win

                    if tcp.data and (dst_port == 443 or src_port == 443):
                        ja3, sni = _compute_ja3(bytes(tcp.data))
                        if ja3 or sni:
                            key = tracker._key(src_ip, dst_ip, src_port, dst_port, proto)
                            tracker.process_packet(timestamp, src_ip, dst_ip, src_port, dst_port, proto, size, flags, win_size)
                            flow = tracker.get_flow(key)
                            if flow: flow.add_tls_info(ja3, sni)
                            continue

                elif proto == 17 and isinstance(ip.data, dpkt.udp.UDP):
                    udp      = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport
                    if src_port == 53 or dst_port == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            key = tracker._key(src_ip, dst_ip, src_port, dst_port, proto)
                            tracker.process_packet(timestamp, src_ip, dst_ip, src_port, dst_port, proto, size, flags, win_size)
                            flow = tracker.get_flow(key)
                            if flow:
                                for q in dns.qd: flow.add_dns_query(q.name)
                                if dns.qr == dpkt.dns.DNS_R: flow.dns_response_codes.append(dns.rcode)
                            continue
                        except Exception:
                            pass

                tracker.process_packet(timestamp, src_ip, dst_ip, src_port, dst_port, proto, size, flags, win_size)
            except Exception:
                continue

    flows = tracker.get_flows()
    flows = _aggregate_flows(flows)

    results = []
    for i, flow in enumerate(flows):
        flow_type = flow.get_flow_type()
        if flow_type == "dns":
            results.append(_extract_dns(flow, i+1))
        elif flow_type == "tls":
            results.append(_extract_tls(flow, i+1))
        else:
            results.append(_extract_general(flow, i+1))

    return results


# ─────────────────────────────────────────────────
# TEST RUNNER
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    import json

    TEST_FILE = r"data/raw/test_ddos.pcap"

    results = parse_pcap(TEST_FILE)
    print(f"Total flows: {len(results)}")

    for i, flow in enumerate(results[:5]):
        print(f"\n── Flow {i+1} ──")
        print(json.dumps(flow["ml_features"], indent=2))