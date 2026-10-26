# API Packet Validator

Standard API tests only check if a server says "200 OK". They don't check if the data was actually kept secure while traveling across the network. 

This repository runs a background digital wiretap (using Scapy) during an automated API test (using Pytest). It intercepts the raw TCP network packets and scans the payloads to ensure secure OAuth tokens aren't accidentally leaking in plain text.

## How It Works
1. **The Test:** Fires a mock authentication request using Python `requests`.
2. **The Sniffer:** A background thread captures packets on port 443.
3. **The Validation:** The test passes only if the API succeeds *and* the token is completely absent from the unencrypted packet layers.

## Usage
Install the dependencies:
```bash
pip install -r requirements.txt
