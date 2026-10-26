import pytest
import requests
from scapy.all import sniff
import threading

API_ENDPOINT = "https://httpbin.org/bearer"
TOKEN = "mock_secure_token_123"

def capture_packets(packet_list, duration=3):
    packets = sniff(filter="tcp port 443", timeout=duration)
    packet_list.extend(packets)

def test_oauth_packet_integrity():
    captured_packets = []
    sniffer_thread = threading.Thread(target=capture_packets, args=(captured_packets,))
    sniffer_thread.start()

    headers = {"Authorization": f"Bearer {TOKEN}"}
    response = requests.get(API_ENDPOINT, headers=headers)
    sniffer_thread.join()

    assert response.status_code == 200, "API Authentication failed"
    assert len(captured_packets) > 0, "No TCP Packets captured during execution"

    for pkt in captured_packets:
        if pkt.haslayer("Raw"):
            raw_payload = pkt.getlayer("Raw").load.decode(errors="ignore")
            assert TOKEN not in raw_payload, "Vulnerability: Token detected in plaintext packet payload"
