from pydantic import BaseModel
from typing import Optional


class Flow(BaseModel):
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str


class Traffic(BaseModel):
    packet_count: int
    total_bytes: int
    average_packet_size: float
    duration_seconds: float
    packet_rate: float


class Threat(BaseModel):
    detected: bool
    prediction: str
    confidence: float
    severity: str


class Alert(BaseModel):
    alert_id: str
    timestamp: str
    flow: Flow
    traffic: Traffic
    threat: Threat
    # Add this at the bottom of shared/schemas.py to test validation:
if __name__ == "__main__":
    # Test creating a sample Alert using the schemas:
    sample_flow = Flow(
        flow_id="FLOW-001",
        source_ip="10.0.0.50",
        destination_ip="104.16.132.229",
        source_port=8390,
        destination_port=80,
        protocol="TCP"
    )

    sample_traffic = Traffic(
        packet_count=14,
        total_bytes=9586,
        average_packet_size=684.71,
        duration_seconds=0.0,
        packet_rate=4324.98
    )

    sample_threat = Threat(
        detected=False,
        prediction="BENIGN",
        confidence=0.98,
        severity="LOW"
    )

    alert = Alert(
        alert_id="ALT-001",
        timestamp="2026-09-04T14:45:00Z",
        flow=sample_flow,
        traffic=sample_traffic,
        threat=sample_threat
    )

    print("✅ Pydantic validation successful! Here is the Alert model:")
    print(alert.model_dump_json(indent=2))