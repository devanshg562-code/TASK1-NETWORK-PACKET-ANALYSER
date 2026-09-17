# CODSOFT Task 1 — Network Packet Analyzer

A Python/Scapy educational packet analyzer for inspecting network traffic.

## Features
- Captures packets from a selected interface.
- Extracts source/destination IP, protocol, ports and packet length.
- Displays a compact table in the terminal.
- Can save a PCAP capture for later analysis.
- Includes an offline PCAP analysis mode.

## Python
Designed for Python 3.13.

## Installation
```bash
python -m pip install -r requirements.txt
```

## Capture live traffic
Run your terminal with the privileges required by your OS:
```bash
python src/packet_analyzer.py --count 20
```

To select an interface:
```bash
python src/packet_analyzer.py --interface "Wi-Fi" --count 20
```

Save a capture:
```bash
python src/packet_analyzer.py --count 50 --pcap captures/capture.pcap
```

## Analyze an existing PCAP
```bash
python src/packet_analyzer.py --read-pcap captures/capture.pcap
```

Only inspect traffic on systems/networks you own or are authorized to monitor.
