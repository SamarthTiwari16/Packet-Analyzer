import argparse
import sys
import struct
import socket

from dpi_types import FiveTuple, AppType, sni_to_app_type
from pcap_reader import PcapReader
from packet_parser import PacketParser
from sni_extractor import SNIExtractor, HTTPHostExtractor

class Flow:
    def __init__(self, tuple_obj):
        self.tuple = tuple_obj
        self.app_type = AppType.UNKNOWN
        self.sni = ""
        self.packets = 0
        self.bytes = 0
        self.blocked = False

class BlockingRules:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_apps = set()
        self.blocked_domains = []

    def block_ip(self, ip: str):
        self.blocked_ips.add(ip)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app_str: str):
        app_str = app_str.upper()
        try:
            app = AppType[app_str]
            self.blocked_apps.add(app)
            print(f"[Rules] Blocked app: {app_str}")
        except KeyError:
            print(f"[Rules] Unknown app: {app_str}")

    def block_domain(self, domain: str):
        self.blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: str, app: AppType, sni: str) -> bool:
        if src_ip in self.blocked_ips: return True
        if app in self.blocked_apps: return True
        for dom in self.blocked_domains:
            if dom in sni: return True
        return False

def print_usage(prog_name):
    print(f"""
DPI Engine - Deep Packet Inspection System
==========================================

Usage: {prog_name} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  {prog_name} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")

def main():
    parser = argparse.ArgumentParser(description="DPI Engine - Deep Packet Inspection System (Single Threaded)")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file")
    parser.add_argument("--block-ip", action="append", default=[], help="Block source IP")
    parser.add_argument("--block-app", action="append", default=[], help="Block application (YouTube, Facebook, etc.)")
    parser.add_argument("--block-domain", action="append", default=[], help="Block domain (substring match)")

    args = parser.parse_args()

    rules = BlockingRules()
    
    for ip in args.block_ip: rules.block_ip(ip)
    for app in args.block_app: rules.block_app(app)
    for dom in args.block_domain: rules.block_domain(dom)

    print("\n")
    print("============================================================")
    print("                    DPI ENGINE v1.0                         ")
    print("============================================================\n")

    reader = PcapReader()
    if not reader.open(args.input):
        print(f"Error: Cannot open input file {args.input}")
        sys.exit(1)

    try:
        out_file = open(args.output, 'wb')
    except IOError:
        print(f"Error: Cannot open output file {args.output}")
        sys.exit(1)

    # Write PCAP header
    hdr = reader.global_header
    fmt = reader.byte_order + "IHHIIII"
    hdr_bytes = struct.pack(fmt, hdr.magic_number, hdr.version_major, hdr.version_minor,
                            hdr.thiszone, hdr.sigfigs, hdr.snaplen, hdr.network)
    out_file.write(hdr_bytes)

    flows = {}
    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats = {}

    print("[DPI] Processing packets...")

    while True:
        phdr, pdata = reader.read_next_packet()
        if not phdr:
            break
            
        total_packets += 1

        parsed = PacketParser.parse(pdata)
        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue

        tuple_obj = FiveTuple(parsed.src_ip, parsed.dest_ip, parsed.src_port, parsed.dest_port, parsed.protocol)

        flow = flows.get(tuple_obj)
        if not flow:
            flow = Flow(tuple_obj)
            flows[tuple_obj] = flow

        flow.packets += 1
        flow.bytes += len(pdata)

        # Try SNI extraction (HTTPS)
        if (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTPS) and not flow.sni and parsed.has_tcp and parsed.dest_port == 443:
            if parsed.payload_length > 5:
                payload = pdata[parsed.payload_offset:]
                sni = SNIExtractor.extract(payload)
                if sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)

        # Try HTTP Host extraction
        if (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTP) and not flow.sni and parsed.has_tcp and parsed.dest_port == 80:
            payload = pdata[parsed.payload_offset:]
            host = HTTPHostExtractor.extract(payload)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)

        # DNS classification
        if flow.app_type == AppType.UNKNOWN and (parsed.dest_port == 53 or parsed.src_port == 53):
            flow.app_type = AppType.DNS

        # Port-based fallback
        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        # Check block rules
        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_obj.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                sn_str = f": {flow.sni}" if flow.sni else ""
                print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({flow.app_type.name}{sn_str})")

        app_stats[flow.app_type] = app_stats.get(flow.app_type, 0) + 1

        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            # Write to output PCAP
            fmt_ph = reader.byte_order + "IIII"
            phdr_bytes = struct.pack(fmt_ph, phdr.ts_sec, phdr.ts_usec, len(pdata), len(pdata))
            out_file.write(phdr_bytes)
            out_file.write(pdata)

    reader.close()
    out_file.close()

    # Print report
    print("\n")
    print("="*60)
    print("                      PROCESSING REPORT                       ")
    print("="*60)
    print(f" Total Packets:      {total_packets:<10}")
    print(f" Forwarded:          {forwarded:<10}")
    print(f" Dropped:            {dropped:<10}")
    print(f" Active Flows:       {len(flows):<10}")
    print("="*60)
    print("                    APPLICATION BREAKDOWN                     ")
    print("="*60)

    # Sort apps
    sorted_apps = sorted(app_stats.items(), key=lambda item: item[1], reverse=True)
    
    for app, count in sorted_apps:
        pct = 100.0 * count / total_packets if total_packets > 0 else 0
        bars = "#" * int(pct / 5)
        print(f" {app.name:<15} {count:>8} {pct:5.1f}%  {bars:<20}")

    print("="*60)

    # Unique SNIs
    print("\n[Detected Applications/Domains]")
    unique_snis = {}
    for flow in flows.values():
        if flow.sni:
            unique_snis[flow.sni] = flow.app_type

    for sni, app in unique_snis.items():
        print(f"  - {sni} -> {app.name}")

    print(f"\nOutput written to: {args.output}\n")

if __name__ == "__main__":
    main()
