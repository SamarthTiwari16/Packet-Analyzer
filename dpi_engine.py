import threading
import queue
import struct
import sys
from collections import defaultdict

from pcap_reader import PcapReader
from packet_parser import PacketParser
from sni_extractor import SNIExtractor, HTTPHostExtractor
from rule_manager import Rules
from dpi_types import FiveTuple, AppType, sni_to_app_type, Packet, Stats

class Config:
    def __init__(self, num_lbs=2, fps_per_lb=2, verbose=False):
        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb
        self.verbose = verbose

class FastPath(threading.Thread):
    def __init__(self, fp_id, in_queue, out_queue, rules, stats):
        super().__init__()
        self.fp_id = fp_id
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.rules = rules
        self.stats = stats
        self.flows = {}
        self.running = True
        self.processed_count = 0

    def stop(self):
        self.running = False

    def run(self):
        while self.running:
            try:
                pkt = self.in_queue.get(timeout=0.1)
                if pkt is None:
                    continue
                
                try:
                    self.processed_count += 1

                    flow = self.flows.get(pkt.tuple)
                    if not flow:
                        class FlowObj: pass
                        flow = FlowObj()
                        flow.app_type = AppType.UNKNOWN
                        flow.sni = ""
                        flow.blocked = False
                        self.flows[pkt.tuple] = flow

                    if (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTPS) and not flow.sni and pkt.parsed.has_tcp and pkt.parsed.dest_port == 443:
                        if pkt.parsed.payload_length > 5:
                            payload = pkt.pdata[pkt.parsed.payload_offset:]
                            sni = SNIExtractor.extract(payload)
                            if sni:
                                flow.sni = sni
                                flow.app_type = sni_to_app_type(sni)

                    if (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTP) and not flow.sni and pkt.parsed.has_tcp and pkt.parsed.dest_port == 80:
                        payload = pkt.pdata[pkt.parsed.payload_offset:]
                        host = HTTPHostExtractor.extract(payload)
                        if host:
                            flow.sni = host
                            flow.app_type = sni_to_app_type(host)

                    if flow.app_type == AppType.UNKNOWN and (pkt.parsed.dest_port == 53 or pkt.parsed.src_port == 53):
                        flow.app_type = AppType.DNS

                    if flow.app_type == AppType.UNKNOWN:
                        if pkt.parsed.dest_port == 443: flow.app_type = AppType.HTTPS
                        elif pkt.parsed.dest_port == 80: flow.app_type = AppType.HTTP

                    if not flow.blocked:
                        if self.rules.is_blocked(pkt.parsed.src_ip, flow.app_type, flow.sni):
                            flow.blocked = True

                    self.stats.record_app(flow.app_type, flow.sni)

                    if flow.blocked:
                        self.stats.inc_dropped(1)
                    else:
                        self.stats.inc_forwarded(1)
                        self.out_queue.put(pkt)
                except Exception as e:
                    print(f"FastPath Error: {e}")
                finally:
                    self.in_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Queue Error: {e}")


class LoadBalancer(threading.Thread):
    def __init__(self, lb_id, in_queue, fp_queues, stats):
        super().__init__()
        self.lb_id = lb_id
        self.in_queue = in_queue
        self.fp_queues = fp_queues
        self.stats = stats
        self.running = True
        self.dispatched_count = 0

    def stop(self):
        self.running = False

    def run(self):
        num_fps = len(self.fp_queues)
        while self.running:
            try:
                pkt = self.in_queue.get(timeout=0.1)
                if pkt is None:
                    continue
                
                try:
                    self.dispatched_count += 1
                    
                    fp_idx = hash(pkt.tuple) % num_fps
                    self.fp_queues[fp_idx].put(pkt)
                except Exception as e:
                    print(f"LoadBalancer Error: {e}")
                finally:
                    self.in_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Queue Error: {e}")

class DPIEngine:
    def __init__(self, config):
        self.config = config
        self.rules = Rules()
        self.stats = Stats()
        self.lb_queues = []
        self.fp_queues = []
        self.out_queue = queue.Queue()
        self.lbs = []
        self.fps = []

    def block_ip(self, ip):
        self.rules.block_ip(ip)

    def block_app(self, app):
        self.rules.block_app(app)

    def block_domain(self, dom):
        self.rules.block_domain(dom)

    def process(self, input_file, output_file):
        for i in range(self.config.num_lbs):
            self.lb_queues.append(queue.Queue(maxsize=10000))
        for i in range(self.config.num_lbs * self.config.fps_per_lb):
            self.fp_queues.append(queue.Queue(maxsize=10000))

        fp_id = 0
        for lb_id in range(self.config.num_lbs):
            my_fps = []
            for _ in range(self.config.fps_per_lb):
                fp = FastPath(fp_id, self.fp_queues[fp_id], self.out_queue, self.rules, self.stats)
                self.fps.append(fp)
                my_fps.append(self.fp_queues[fp_id])
                fp.start()
                fp_id += 1
            
            lb = LoadBalancer(lb_id, self.lb_queues[lb_id], my_fps, self.stats)
            self.lbs.append(lb)
            lb.start()
            
        print(f"DPI ENGINE (Python) - LBs: {self.config.num_lbs}, FPs/LB: {self.config.fps_per_lb}, Total FPs: {len(self.fps)}")
        
        reader = PcapReader()
        if not reader.open(input_file):
            print(f"Error opening {input_file}")
            return False
            
        try:
            out_f = open(output_file, 'wb')
        except:
            return False
            
        hdr = reader.global_header
        fmt = reader.byte_order + "IHHIIII"
        hdr_bytes = struct.pack(fmt, hdr.magic_number, hdr.version_major, hdr.version_minor,
                                hdr.thiszone, hdr.sigfigs, hdr.snaplen, hdr.network)
        out_f.write(hdr_bytes)
        
        def writer_thread():
            while True:
                try:
                    pkt = self.out_queue.get(timeout=0.1)
                    if pkt is None:
                        break
                    try:
                        fmt_ph = reader.byte_order + "IIII"
                        phdr_bytes = struct.pack(fmt_ph, pkt.phdr.ts_sec, pkt.phdr.ts_usec, len(pkt.pdata), len(pkt.pdata))
                        out_f.write(phdr_bytes)
                        out_f.write(pkt.pdata)
                    finally:
                        self.out_queue.task_done()
                except queue.Empty:
                    if not getattr(threading.current_thread(), "running", True):
                        break
                except Exception as e:
                    print(f"Queue Error: {e}")
        
        writer = threading.Thread(target=writer_thread)
        writer.running = True
        writer.start()
        
        print("[Reader] Processing packets...")
        total_packets = 0
        total_bytes = 0
        tcp_count = 0
        udp_count = 0
        
        while True:
            phdr, pdata = reader.read_next_packet()
            if not phdr:
                break
                
            total_packets += 1
            total_bytes += len(pdata)
            parsed = PacketParser.parse(pdata)
            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue
                
            if parsed.has_tcp: tcp_count += 1
            if parsed.has_udp: udp_count += 1
                
            tuple_obj = FiveTuple(parsed.src_ip, parsed.dest_ip, parsed.src_port, parsed.dest_port, parsed.protocol)
            class PktWrapper: pass
            pkt = PktWrapper()
            pkt.phdr = phdr
            pkt.pdata = pdata
            pkt.parsed = parsed
            pkt.tuple = tuple_obj
            
            lb_idx = hash(tuple_obj) % self.config.num_lbs
            self.lb_queues[lb_idx].put(pkt)
            
        print(f"[Reader] Done reading {total_packets} packets")
        
        for q in self.lb_queues: q.join()
        for q in self.fp_queues: q.join()
        
        for lb in self.lbs: lb.stop()
        for lb in self.lbs: lb.join()
        
        for fp in self.fps: fp.stop()
        for fp in self.fps: fp.join()
        
        self.out_queue.join()
        writer.running = False
        writer.join()
        
        reader.close()
        out_f.close()
        
        print("\n" + "="*60)
        print(" PROCESSING REPORT")
        print("="*60)
        print(f" Total Packets:      {total_packets:<10}")
        print(f" Total Bytes:        {total_bytes:<10}")
        print(f" TCP Packets:        {tcp_count:<10}")
        print(f" UDP Packets:        {udp_count:<10}")
        print("="*60)
        print(f" Forwarded:          {self.stats.forwarded:<10}")
        print(f" Dropped:            {self.stats.dropped:<10}")
        print("="*60)
        print(" THREAD STATISTICS")
        for i, lb in enumerate(self.lbs):
            print(f"   LB{i} dispatched:   {lb.dispatched_count:<10}")
        for i, fp in enumerate(self.fps):
            print(f"   FP{i} processed:    {fp.processed_count:<10}")
            
        print("="*60)
        print(" APPLICATION BREAKDOWN")
        print("="*60)
        
        sorted_apps = sorted(self.stats.app_counts.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = 100.0 * count / total_packets if total_packets > 0 else 0
            bars = "#" * int(pct/5)
            print(f" {app.name:<15} {count:>8} {pct:5.1f}%  {bars:<20}")
            
        print("="*60)
        print("\n[Detected Domains/SNIs]")
        for sni, app in self.stats.detected_snis.items():
            print(f"  - {sni} -> {app.name}")
            
        return True
