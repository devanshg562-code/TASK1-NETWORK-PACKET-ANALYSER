#!/usr/bin/env python3
"""CODSOFT Task 1: Educational network packet analyzer."""
import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw, sniff, rdpcap, wrpcap


def protocol(pkt):
    if ARP in pkt:
        return "ARP"
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    if DNS in pkt:
        return "DNS"
    if IP in pkt:
        return str(pkt[IP].proto)
    if IPv6 in pkt:
        return "IPv6"
    return "OTHER"


def endpoints(pkt):
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    elif ARP in pkt:
        src, dst = pkt[ARP].psrc, pkt[ARP].pdst
    else:
        return "-", "-"
    return src, dst


def ports(pkt):
    if TCP in pkt:
        return pkt[TCP].sport, pkt[TCP].dport
    if UDP in pkt:
        return pkt[UDP].sport, pkt[UDP].dport
    return "-", "-"


def packet_row(i, pkt):
    src, dst = endpoints(pkt)
    sport, dport = ports(pkt)
    proto = protocol(pkt)
    return i, src, dst, proto, sport, dport, len(pkt)


def print_packets(packets):
    header = f"{'#':>3} {'SOURCE':<22} {'DESTINATION':<22} {'PROTO':<7} {'SPORT':>6} {'DPORT':>6} {'LEN':>6}"
    print(header)
    print("-" * len(header))
    counts = Counter()
    for i, pkt in enumerate(packets, 1):
        row = packet_row(i, pkt)
        print(f"{row[0]:>3} {str(row[1])[:22]:<22} {str(row[2])[:22]:<22} "
              f"{row[3]:<7} {str(row[4]):>6} {str(row[5]):>6} {row[6]:>6}")
        counts[row[3]] += 1
    print("\nProtocol summary:")
    for proto, count in counts.most_common():
        print(f"  {proto}: {count}")


def main():
    ap = argparse.ArgumentParser(description="Educational network packet analyzer")
    ap.add_argument("--interface", help="Interface to sniff on")
    ap.add_argument("--count", type=int, default=10, help="Number of packets to capture")
    ap.add_argument("--timeout", type=int, default=30, help="Capture timeout in seconds")
    ap.add_argument("--pcap", help="Save captured packets to a PCAP file")
    ap.add_argument("--read-pcap", help="Analyze an existing PCAP instead of live capture")
    args = ap.parse_args()

    if args.read_pcap:
        path = Path(args.read_pcap)
        if not path.exists():
            raise SystemExit(f"PCAP not found: {path}")
        packets = rdpcap(str(path))
    else:
        print(f"Starting capture at {datetime.now().isoformat(timespec='seconds')}")
        print("Press Ctrl+C to stop early if needed.")
        try:
            packets = sniff(iface=args.interface, count=args.count, timeout=args.timeout)
        except PermissionError:
            raise SystemExit("Capture permission denied. Run with the privileges required by your OS.")
        except Exception as exc:
            raise SystemExit(f"Capture failed: {exc}")

    print_packets(packets)
    if args.pcap and not args.read_pcap:
        out = Path(args.pcap)
        out.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(out), packets)
        print(f"\nSaved PCAP: {out}")


if __name__ == "__main__":
    main()
