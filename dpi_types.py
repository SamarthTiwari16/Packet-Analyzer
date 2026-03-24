import enum
from dataclasses import dataclass, field
import threading

class AppType(enum.Enum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22

def sni_to_app_type(sni: str) -> AppType:
    sni = sni.lower()
    if "youtube" in sni or "googlevideo" in sni:
        return AppType.YOUTUBE
    if "facebook" in sni or "fbcdn" in sni:
        return AppType.FACEBOOK
    if "google" in sni:
        return AppType.GOOGLE
    if "twitter" in sni or "twimg" in sni:
        return AppType.TWITTER
    if "instagram" in sni:
        return AppType.INSTAGRAM
    if "netflix" in sni or "nflxvideo" in sni:
        return AppType.NETFLIX
    if "amazon" in sni or "aws" in sni:
        return AppType.AMAZON
    if "microsoft" in sni or "live" in sni or "bing" in sni:
        return AppType.MICROSOFT
    if "apple" in sni or "icloud" in sni:
        return AppType.APPLE
    if "whatsapp" in sni:
        return AppType.WHATSAPP
    if "telegram" in sni:
        return AppType.TELEGRAM
    if "tiktok" in sni or "bytecdn" in sni:
        return AppType.TIKTOK
    if "spotify" in sni:
        return AppType.SPOTIFY
    if "zoom" in sni:
        return AppType.ZOOM
    if "discord" in sni:
        return AppType.DISCORD
    if "github" in sni:
        return AppType.GITHUB
    if "cloudflare" in sni:
        return AppType.CLOUDFLARE
    
    return AppType.UNKNOWN

@dataclass
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int

    def __hash__(self):
        # Implement a consistent hash for Load Balancing
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other):
        if not isinstance(other, FiveTuple):
            return False
        return (self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol)

    def reverse(self):
        return FiveTuple(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)

@dataclass
class Packet:
    id: int
    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    data: bytes
    tcp_flags: int = 0
    payload_offset: int = 0
    payload_length: int = 0

@dataclass
class FlowEntry:
    tuple: FiveTuple = None
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False

class Stats:
    def __init__(self):
        self._total_packets = 0
        self._total_bytes = 0
        self._forwarded = 0
        self._dropped = 0
        self._tcp_packets = 0
        self._udp_packets = 0

        # Protect aggregate operations
        self.lock = threading.Lock()
        
        # Per-app stats
        self.app_counts = {}
        self.detected_snis = {}

    def inc_total_packets(self, amount=1):
        with self.lock:
            self._total_packets += amount

    def inc_total_bytes(self, amount):
        with self.lock:
            self._total_bytes += amount

    def inc_forwarded(self, amount=1):
        with self.lock:
            self._forwarded += amount

    def inc_dropped(self, amount=1):
        with self.lock:
            self._dropped += amount

    def inc_tcp_packets(self, amount=1):
        with self.lock:
            self._tcp_packets += amount

    def inc_udp_packets(self, amount=1):
        with self.lock:
            self._udp_packets += amount

    def record_app(self, app: AppType, sni: str):
        with self.lock:
            self.app_counts[app] = self.app_counts.get(app, 0) + 1
            if sni:
                self.detected_snis[sni] = app

    @property
    def total_packets(self):
        with self.lock: return self._total_packets

    @property
    def total_bytes(self):
        with self.lock: return self._total_bytes

    @property
    def forwarded(self):
        with self.lock: return self._forwarded

    @property
    def dropped(self):
        with self.lock: return self._dropped

    @property
    def tcp_packets(self):
        with self.lock: return self._tcp_packets

    @property
    def udp_packets(self):
        with self.lock: return self._udp_packets
