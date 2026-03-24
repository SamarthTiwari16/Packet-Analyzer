import argparse
import sys
from dpi_engine import DPIEngine, Config

def main():
    parser = argparse.ArgumentParser(description="DPI Engine v2.0 - Multi-threaded Deep Packet Inspection (Python version)")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file")
    parser.add_argument("--block-ip", action="append", default=[], help="Block source IP")
    parser.add_argument("--block-app", action="append", default=[], help="Block application (YouTube, Facebook, etc.)")
    parser.add_argument("--block-domain", action="append", default=[], help="Block domain (substring match)")
    parser.add_argument("--lbs", type=int, default=2, help="Number of load balancer threads (default: 2)")
    parser.add_argument("--fps", type=int, default=2, help="FP threads per LB (default: 2)")

    args = parser.parse_args()

    cfg = Config(num_lbs=args.lbs, fps_per_lb=args.fps)
    engine = DPIEngine(cfg)

    for ip in args.block_ip:
        engine.block_ip(ip)
    
    for app in args.block_app:
        engine.block_app(app)
        
    for dom in args.block_domain:
        engine.block_domain(dom)

    if not engine.process(args.input, args.output):
        sys.exit(1)

    print(f"\nOutput written to: {args.output}")

if __name__ == "__main__":
    main()
