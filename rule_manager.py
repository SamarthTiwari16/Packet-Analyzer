import threading
from dpi_types import AppType

class Rules:
    def __init__(self):
        self.lock = threading.Lock()
        self.blocked_ips = set()
        self.blocked_apps = set()
        self.blocked_domains = []

    def block_ip(self, ip: str):
        with self.lock:
            self.blocked_ips.add(ip)
            print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app_str: str):
        app_str = app_str.upper()
        with self.lock:
            try:
                app = AppType[app_str]
                self.blocked_apps.add(app)
                print(f"[Rules] Blocked app: {app_str}")
            except KeyError:
                print(f"[Rules] Unknown app: {app_str}")

    def block_domain(self, domain: str):
        with self.lock:
            self.blocked_domains.append(domain)
            print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: str, app: AppType, sni: str) -> bool:
        with self.lock:
            if src_ip in self.blocked_ips:
                return True
            if app in self.blocked_apps:
                return True
            for dom in self.blocked_domains:
                if dom in sni:
                    return True
            return False
