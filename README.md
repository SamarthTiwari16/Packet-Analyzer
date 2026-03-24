# DPI Engine - Deep Packet Inspection System

This document explains everything about this project - from basic networking concepts to the complete code architecture. After reading this, we should understand exactly how packets flow through the system without needing to read the code.

## Table of Contents
1. What is DPI?
2. Networking Background
3. Project Overview
4. File Structure
5. The Journey of a Packet (Simple Version)
6. The Journey of a Packet (Multi-threaded Version)
7. Deep Dive: Each Component
8. How SNI Extraction Works
9. How Blocking Works
10. Building and Running
11. Understanding the Output
12. Extending the Project

---

## 1. What is DPI?
Deep Packet Inspection (DPI) is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks inside the packet payload.

**Real-World Uses:**
- **ISPs:** Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises:** Block social media on office networks
- **Parental Controls:** Block inappropriate websites
- **Security:** Detect malware or intrusion attempts

**What Our DPI Engine Does:**
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

**The Network Stack (Layers)**
When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

**A Packet's Structure**
Every network packet is like a Russian nesting doll - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**The Five-Tuple**
A connection (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|---|---|---|
| Source IP | `192.168.1.100` | Who is sending |
| Destination IP | `172.217.14.206` | Where it's going |
| Source Port | `54321` | Sender's application identifier |
| Destination Port | `443` | Service being accessed (443 = HTTPS) |
| Protocol | `TCP (6)` | TCP or UDP |

**Why is this important?**
* All packets with the same 5-tuple belong to the same connection
* If we block one packet of a connection, we should block all of them
* This is how we "track" conversations between computers

**What is SNI?**
Server Name Indication (SNI) is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:
1. Your browser sends a "Client Hello" message
2. This message includes the domain name in plaintext (not encrypted yet!)
3. The server uses this to know which certificate to send

```text
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```
This is the key to DPI: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

**What This Project Does**
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

**Two Versions**
| Version | File | Use Case |
|---|---|---|
| Simple (Single-threaded) | `main_working.py` | Learning, logic verification, small captures |
| Multi-threaded | `main.py` | Production, large high-speed captures |

---

## 4. File Structure
```text
packet_analyzer/
├── pcap_reader.py             # PCAP file reading/writing logic
├── packet_parser.py           # Network protocol parsing (IP, TCP)
├── sni_extractor.py           # TLS/HTTP header inspection
├── dpi_types.py               # FiveTuple, AppType, and Stats tracking
├── rule_manager.py            # Blocking logic rules
├── dpi_engine.py              # Main orchestrator (Multi-thread classes)
├── main_working.py            # ★ SIMPLE VERSION ★
├── main.py                    # ★ MULTI-THREADED VERSION ★
├── generate_test_pcap.py      # Creates test data captures
├── test_dpi.pcap              # Sample capture with various testing traffic
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet (Simple Version)
Let's trace a single packet through `main_working.py`:

**Step 1: Read PCAP File**
```python
reader = PcapReader()
reader.open("capture.pcap")
```
**What happens:**
* Open the file in binary mode `rb`
* Read the 24-byte global header (magic number, version, etc.) using `struct`
* Verify it's a valid PCAP file

**Step 2: Read Each Packet**
```python
while True:
    phdr, pdata = reader.read_next_packet()
    if not phdr:
        break
```
**What happens:**
* Read 16-byte packet header
* Read N bytes of packet data (N = header's included length)
* Break loop when EOF

**Step 3: Parse Protocol Headers**
```python
parsed = PacketParser.parse(pdata)
```
**What happens (in packet_parser.py):**
* `pdata` bytes:
  * `[0-13]` Ethernet Header
  * `[14-33]` IP Header  
  * `[34-53]` TCP Header
  * `[54+]` Payload
* Parses IP length, TTL, protocols. Parses TCP/UDP ports.

**Step 4: Create Five-Tuple and Look Up Flow**
```python
tuple_obj = FiveTuple(parsed.src_ip, parsed.dest_ip, parsed.src_port, parsed.dest_port, parsed.protocol)

flow = flows.get(tuple_obj)  # Get or create
if not flow:
    flow = FlowEntry()
    flows[tuple_obj] = flow
```
**What happens:**
* The flow table is an in-memory dictionary.
* If this 5-tuple exists, we fetch the existing flow history.
* All packets with the same 5-tuple share the same flow object references.

**Step 5: Extract SNI (Deep Packet Inspection)**
```python
# For HTTPS traffic (port 443)
if flow.app_type == AppType.UNKNOWN and parsed.dest_port == 443:
    if parsed.payload_length > 5:
        payload = pdata[parsed.payload_offset:]
        sni = SNIExtractor.extract(payload)
        if sni:
            flow.sni = sni                    # "www.youtube.com"
            flow.app_type = sni_to_app_type(sni) # AppType.YOUTUBE
```

**Step 6: Check Blocking Rules**
```python
if not flow.blocked:
    if rules.is_blocked(parsed.src_ip, flow.app_type, flow.sni):
        flow.blocked = True
```

**Step 7: Forward or Drop**
```python
if flow.blocked:
    dropped += 1
else:
    forwarded += 1
    # Write packet header and data back to output file
    out_f.write(phdr_bytes)
    out_f.write(pdata)
```
---


## 6. The Journey of a Packet (Multi-threaded Version)
The multi-threaded version (`main.py` -> `dpi_engine.py`) adds parallelism for high performance using Python's native `threading` module:

**Architecture Overview**
```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

**Why consistent hashing matters:**
Python computes `hash(pkt.tuple)`.
Every packet from connection A will yield the same hash value, meaning the LoadBalancer will ALWAYS send it directly to `FP2`.
`FP2` then builds a dictionary locally that monitors tracking without risking racing other threads.

**Thread-Safe Queue (Python module)**
The magic that makes multi-threading work is Python's thread-safe queue:
```python
import queue
self.in_queue = queue.Queue(maxsize=10000)

self.in_queue.put(item)         # Worker locks and adds
item = self.in_queue.get()      # Threads efficiently block until available
self.in_queue.task_done()       # Signals the queue that item processing is done
```

---

## 7. Deep Dive: Each Component

**`pcap_reader.py`**
Handles reading Wireshark .pcap binaries completely natively utilizing Python `struct.unpack()`.

**`packet_parser.py`**
Slices raw bytes without complex overhead.
```python
# Unpack IPv4 Header specifically
iph = struct.unpack('!BBHHHBBH4s4s', ip_header_bytes)
parsed.protocol = iph[6]
parsed.src_ip = iph[8]
parsed.dest_ip = iph[9]
```

**`dpi_types.py`**
Manages `AppType` Enums and our `Stats` tracking using `threading.Lock()` to prevent race conditions during reporting.

---

## 8. How SNI Extraction Works
We can only extract encrypted SNIs directly from the TLS **Client Hello** payload!

```python
def extract(payload: bytes):
    # Check TLS record header
    if payload[0] != 0x16: return None  # Not handshake
    if payload[5] != 0x01: return None  # Not Client Hello
    
    offset = 43  # Skip to session ID
    
    # Python struct allows us to quickly skip variable lengths!
    session_len = payload[offset]
    offset += 1 + session_len
    ...
    # Hunt for SNI extension (type 0x0000)
    if ext_type == 0x0000:
        sni_len = struct.unpack('!H', payload[offset+3:offset+5])[0]
        return payload[offset+5:offset+5+sni_len].decode('utf-8', 'ignore')
```

---

## 9. How Blocking Works

**Rule Types:**
| Rule Type | Example | What it Blocks |
|---|---|---|
| **IP** | `192.168.1.50` | All traffic originating from this source |
| **App** | `YouTube` | All connections cleanly mapped to the YouTube AppType enum |
| **Domain** | `tiktok` | Uses substring logic; blocks any SNI payload containing "tiktok" |

**Flow-Based Blocking:**
When Packet 1 and 2 pass through, they don't have SNI data yet so we FORWARD them. When Packet 4 triggers the ClientHello mapping it to YouTube, we trigger `flow.blocked = True`. All subsequent packets of that flow will hit `flow.blocked` instantaneously and DROP. The connection completely crashes on the user's side.

---

## 10. Building and Running

**Prerequisites**
- **Python 3.7+**
- No external libraries needed! Uses ONLY standard modules.
- Absolutely no C++ compilers (`g++`/`clang++`) required!

**Running**
Simple Version:
```bash
python main_working.py test_dpi.pcap output.pcap
```
Multi-threaded Version:
```bash
python main.py test_dpi.pcap output.pcap
```

With blocking:
```bash
python main.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

Configure threads (multi-threaded only):
```bash
python main.py input.pcap output.pcap --lbs 4 --fps 4
# Creates 4 LB threads * 4 FP threads = 16 processing threads
```

Creating Test Data:
```bash
python generate_test_pcap.py
# Instantly builds test_dpi.pcap with standard test flows
```

---

## 11. Understanding the Output
The output prints identically between versions, generating comprehensive reporting analytics:

```text
DPI ENGINE (Python) - LBs: 2, FPs/LB: 2, Total FPs: 4
[Reader] Processing packets...
[Reader] Done reading 77 packets

============================================================
 PROCESSING REPORT
============================================================
 Total Packets:      77
 Total Bytes:        5738
 TCP Packets:        73
 UDP Packets:        4
============================================================
 Forwarded:          76
 Dropped:            1
============================================================
 THREAD STATISTICS
   LB0 dispatched:   35
   LB1 dispatched:   42
   FP0 processed:    35
...
============================================================
 APPLICATION BREAKDOWN
============================================================
 HTTPS                 37  48.1%  #########
 UNKNOWN               16  20.8%  ####
 ...
 YOUTUBE                1   1.3%
 FACEBOOK               1   1.3%
...
[Detected Domains/SNIs]
  - www.google.com -> GOOGLE
  - www.youtube.com -> YOUTUBE
```

**What Each Section Means:**
1. **Thread Statistics**: Demonstrates precisely how your traffic scaled laterally.
2. **Application Breakdown**: Automatically buckets and generates a lightweight histogram mapping traffic.
3. **Detected Domains**: Visual map proving what domains triggered what engine `AppType`.

---

## 12. Extending the Project

**Ideas for Improvement**

1. **Add More App Signatures**
   ```python
   # In dpi_types.py
   if "twitch" in sni.lower():
       return AppType.TWITCH
   ```

2. **Add Bandwidth Throttling**
   ```python
   # Instead of DROP, delay packets using the time module
   import time
   if should_throttle(flow):
       time.sleep(0.01) # Sleep block thread for 10ms
   ```

3. **Add Live Statistics Dashboard**
   ```python
   # Separate thread printing stats every second
   import time, threading
   def stats_thread():
       while running:
           print_stats()
           time.sleep(1)
   ```

4. **Add QUIC/HTTP3 Support**
   QUIC uses UDP on port 443! SNI is present in the initial payload but encrypted/formatted entirely differently. Add a new `QUICExtractor` to parse UDP packets bridging this gap.

5. **Add Persistent Rules**
   Save Rules to a `config.json` via the `json` library, and load them onto the orchestrator at startup.

---

**Author:** Samarth Tiwari  
**Email:** samarthtiwarij16@gmail.com
