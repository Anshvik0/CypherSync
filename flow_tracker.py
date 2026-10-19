# flow_tracker.py
# Groups individual packets into flows (conversations)

class Flow:
    """Represents one network conversation between two computers"""
    
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        # Who is talking to whom
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Stats we collect
        self.packet_count = 0       # How many packets
        self.byte_count = 0         # How many bytes total
        self.start_time = None      # When did it start
        self.end_time = None        # When did it end
        
        # TCP flags (only for TCP flows)
        self.syn_count = 0          # SYN packets (connection starts)
        self.ack_count = 0          # ACK packets (normal data)
        self.fin_count = 0          # FIN packets (connection ends normally)
        self.rst_count = 0          # RST packets (connection ended abruptly)
        
        # List of each packet's size (for later analysis)
        self.packet_sizes = []
        
        # List of time gaps between packets
        self.inter_arrival_times = []
        self.last_packet_time = None
    
    def add_packet(self, timestamp, size, flags=0):
        """Call this every time a new packet belongs to this flow"""
        
        # Set start time on first packet
        if self.start_time is None:
            self.start_time = timestamp
        
        # Always update end time
        self.end_time = timestamp
        
        # Calculate time gap from last packet
        if self.last_packet_time is not None:
            gap = timestamp - self.last_packet_time
            self.inter_arrival_times.append(gap)
        self.last_packet_time = timestamp
        
        # Update counts
        self.packet_count += 1
        self.byte_count += size
        self.packet_sizes.append(size)
        
        # Count TCP flags
        if self.protocol == 6:  # 6 = TCP
            if flags & 0x02:    # SYN flag
                self.syn_count += 1
            if flags & 0x10:    # ACK flag
                self.ack_count += 1
            if flags & 0x01:    # FIN flag
                self.fin_count += 1
            if flags & 0x04:    # RST flag
                self.rst_count += 1
    
    def duration(self):
        """How long did this conversation last (in seconds)?"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0
    
    def summary(self):
        """Print a human-readable summary of this flow"""
        proto = "TCP" if self.protocol == 6 else "UDP"
        dur = self.duration()
        return (
            f"{self.src_ip}:{self.src_port} → "
            f"{self.dst_ip}:{self.dst_port} "
            f"[{proto}] | "
            f"Packets: {self.packet_count} | "
            f"Bytes: {self.byte_count} | "
            f"Duration: {dur:.2f}s | "
            f"SYN: {self.syn_count} FIN: {self.fin_count} RST: {self.rst_count}"
        )


class FlowTracker:
    """Manages all flows — groups packets into the right flow"""
    
    def __init__(self):
        self.flows = {}  # Dictionary: flow_key → Flow object
    
    def _make_key(self, src_ip, dst_ip, src_port, dst_port, proto):
        """
        Create a unique ID for this conversation.
        We sort the two sides so A→B and B→A are the same flow.
        """
        side_a = (src_ip, src_port)
        side_b = (dst_ip, dst_port)
        
        # Always put the smaller one first (so direction doesn't matter)
        if side_a > side_b:
            side_a, side_b = side_b, side_a
        
        return (side_a, side_b, proto)
    
    def process_packet(self, timestamp, src_ip, dst_ip, 
                       src_port, dst_port, proto, size, flags=0):
        """Call this for every packet — it sorts it into the right flow"""
        
        key = self._make_key(src_ip, dst_ip, src_port, dst_port, proto)
        
        # If this flow doesn't exist yet, create it
        if key not in self.flows:
            self.flows[key] = Flow(src_ip, dst_ip, src_port, dst_port, proto)
        
        # Add this packet to the flow
        self.flows[key].add_packet(timestamp, size, flags)
    
    def get_all_flows(self):
        """Return list of all flows"""
        return list(self.flows.values())
    
    def print_summary(self):
        """Print all flows sorted by byte count"""
        flows = sorted(self.get_all_flows(), 
                      key=lambda f: f.byte_count, reverse=True)
        print(f"\nTotal flows found: {len(flows)}\n")
        for i, flow in enumerate(flows):
            print(f"Flow {i+1}: {flow.summary()}")