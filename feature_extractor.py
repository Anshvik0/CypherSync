# feature_extractor.py
import json
import numpy as np

def extract_features(flow, flow_index=1):
    """
    Extracts flow + traffic sections
    matching Person 1's agreed JSON format exactly.
    """

    duration = flow.duration()
    duration = max(duration, 0.001)

    avg_pkt_size = round(flow.byte_count / flow.packet_count, 2) \
                   if flow.packet_count > 0 else 0

    packet_rate = round(flow.packet_count / duration, 2)

    return {
        "flow": {
            "flow_id":          f"FLOW-{flow_index:03d}",
            "source_ip":        flow.src_ip,
            "destination_ip":   flow.dst_ip,
            "source_port":      flow.src_port,
            "destination_port": flow.dst_port,
            "protocol":         "TCP" if flow.protocol == 6 else "UDP"
        },
        "traffic": {
            "packet_count":        flow.packet_count,
            "total_bytes":         flow.byte_count,
            "average_packet_size": avg_pkt_size,
            "duration_seconds":    round(duration, 2),
            "packet_rate":         packet_rate
        }
    }


def extract_all(flows):
    """Extract features from all flows"""
    return [extract_features(f, i+1) for i, f in enumerate(flows)]


def save_to_json(all_features, output_file="features_output.json"):
    """Save extracted features to JSON file"""
    output = {
        "total_flows": len(all_features),
        "flows": all_features
    }
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n✅ Saved to: {output_file}")
    print(f"   Total flows: {len(all_features)}")