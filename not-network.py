import sys
import os
import subprocess
import ctypes
import psutil
import re
import json
import socket
import time
import zipfile
import shutil
import logging
import logging.handlers
import winreg
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout,
                              QWidget, QSystemTrayIcon, QMenu, QFileDialog)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl, pyqtSlot, QTimer, QEvent
from PyQt6.QtGui import QIcon, QAction, QKeySequence, QShortcut
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineSettings
from PyQt6.QtWebChannel import QWebChannel

# ─────────────────────────────────────────────
#  SINGLE INSTANCE
# ─────────────────────────────────────────────
MUTEX_NAME = "Global\\NOTEVIL_NET_SINGLE_INSTANCE"
_mutex_handle = None

def ensure_single_instance():
    global _mutex_handle
    _mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, False, MUTEX_NAME)
    if ctypes.windll.kernel32.GetLastError() == 183:
        ctypes.windll.user32.MessageBoxW(
            None,
            "not NETWORK is already running.\nCheck the system tray.",
            "Already Running", 0x00000030)
        sys.exit(0)

# ─────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def get_base_path():
    if getattr(sys, 'frozen', False): return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR      = get_base_path()
CORE_EXE      = os.path.join(BASE_DIR, "core", "sing-box.exe")
PROFILES_DIR  = os.path.join(BASE_DIR, "config", "profiles")
ICON_PATH     = os.path.join(BASE_DIR, "icons", "not_network.ico")
SETTINGS_JSON = os.path.join(BASE_DIR, "config", "settings.json")
HISTORY_JSON  = os.path.join(BASE_DIR, "config", "history.json")
TAGS_JSON     = os.path.join(BASE_DIR, "config", "tags.json")
LOGS_DIR      = os.path.join(BASE_DIR, "logs")
os.makedirs(PROFILES_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

CLASH_API_PORT   = 9090
CLASH_API_SECRET = "notevil_secret"
MIXED_PROXY_PORT = 12334   # local SOCKS/HTTP proxy for MIXED mode
HEALTH_CHECK_HOST = "1.1.1.1"
HEALTH_CHECK_PORT = 443
HEALTH_CHECK_INTERVAL = 30
HEALTH_CHECK_FAILS_BEFORE_ALERT = 3
HISTORY_LIMIT = 50

# ─────────────────────────────────────────────
#  LOGGING TO FILE
# ─────────────────────────────────────────────
def setup_logging():
    log_path = os.path.join(LOGS_DIR, "notevil.log")
    handler = logging.handlers.TimedRotatingFileHandler(
        log_path, when="midnight", interval=1, backupCount=7, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    return logging.getLogger("notevil")

log = setup_logging()
log.info("=" * 60)
APP_VERSION = "v6.3"
log.info(f"NOTEVIL//NET {APP_VERSION} started")

# ─────────────────────────────────────────────
#  AUTOSTART (Windows registry)
# ─────────────────────────────────────────────
AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_NAME = "NotEvilNet"

def autostart_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0, winreg.KEY_READ) as k:
            winreg.QueryValueEx(k, AUTOSTART_NAME)
            return True
    except FileNotFoundError:
        return False
    except Exception:
        return False

def set_autostart(enabled: bool) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            if enabled:
                script = os.path.abspath(sys.argv[0])
                if getattr(sys, 'frozen', False):
                    cmd = f'"{sys.executable}" --minimized'
                else:
                    cmd = f'"{sys.executable}" "{script}" --minimized'
                winreg.SetValueEx(k, AUTOSTART_NAME, 0, winreg.REG_SZ, cmd)
            else:
                try: winreg.DeleteValue(k, AUTOSTART_NAME)
                except FileNotFoundError: pass
        return True
    except Exception as e:
        log.error(f"set_autostart: {e}")
        return False

# ─────────────────────────────────────────────
#  ROUTING
# ─────────────────────────────────────────────
ROUTING_RULES = {
    "Global": {
        "rules": [
            {"action": "sniff"},
            {"action": "hijack-dns", "protocol": "dns"}
        ],
        "final": "proxy",
        "auto_detect_interface": True,
        "default_domain_resolver": "dns-direct"
    },
    "Rule": {
        "rules": [
            {"action": "sniff"},
            {"action": "hijack-dns", "protocol": "dns"},
            {"ip_is_private": True, "outbound": "direct"},
        ],
        "final": "proxy",
        "auto_detect_interface": True,
        "default_domain_resolver": "dns-direct"
    },
    "Direct": {
        "rules": [
            {"action": "sniff"},
            {"action": "hijack-dns", "protocol": "dns"}
        ],
        "final": "direct",
        "auto_detect_interface": True,
        "default_domain_resolver": "dns-direct"
    }
}

# ─────────────────────────────────────────────
#  KEY PARSER  (returns config, summary dict, or error)
# ─────────────────────────────────────────────
def parse_key(key: str):
    """Returns (config, summary_dict) or (None, error_string)."""
    key = key.strip()
    if not key:
        return None, "Empty key"
    if '#' in key:
        key = key.split('#', 1)[0]

    if key.startswith("hysteria2://") or key.startswith("hy2://"):
        try:
            parsed = urlparse(key)
            password = unquote(parsed.username or "")
            host     = parsed.hostname or ""
            port     = parsed.port or 443
            params   = parse_qs(parsed.query)
            sni      = params.get("sni", [host])[0]
            insecure = params.get("insecure", ["1"])[0] in ("1", "true")
            obfs     = params.get("obfs", [""])[0]
            obfs_pwd = params.get("obfs-password", [""])[0]

            if not host or not password:
                return None, "Invalid hysteria2 key: missing host or password"

            outbound = {
                "type": "hysteria2", "tag": "proxy",
                "server": host, "server_port": port,
                "password": password, "up_mbps": 100, "down_mbps": 100,
                "tls": {"enabled": True, "server_name": sni, "insecure": insecure}
            }
            if obfs == "salamander" and obfs_pwd:
                outbound["obfs"] = {"type": "salamander", "password": obfs_pwd}
            summary = {
                "protocol": "HYSTERIA2",
                "server": f"{host}:{port}",
                "sni": sni,
                "obfs": "salamander" if obfs == "salamander" else "none"
            }
            return outbound, summary
        except Exception as e:
            return None, f"Parse error: {e}"

    if key.startswith("vless://"):
        try:
            parsed = urlparse(key)
            uuid   = unquote(parsed.username or "")
            host   = parsed.hostname or ""
            port   = parsed.port or 443
            params = parse_qs(parsed.query)

            if not host or not uuid:
                return None, "Invalid vless key: missing host or UUID"

            uuid_re = re.compile(r"^[0-9a-fA-F-]{36}$")
            if not uuid_re.match(uuid):
                return None, "Invalid UUID format"

            security = params.get("security", ["none"])[0].lower()
            sni      = params.get("sni",      [host])[0]
            fp       = params.get("fp",       ["chrome"])[0]
            pbk      = params.get("pbk",      [""])[0]
            sid      = params.get("sid",      [""])[0]
            flow     = params.get("flow",     [""])[0]
            network  = params.get("type",     ["tcp"])[0].lower()

            # Reality validation
            if security == "reality":
                if not pbk:
                    return None, "Reality key missing 'pbk' (public key)"
                if len(pbk) != 43:
                    return None, f"Reality pbk must be 43 chars (got {len(pbk)})"

            outbound = {
                "type": "vless", "tag": "proxy",
                "server": host, "server_port": port,
                "uuid": uuid, "packet_encoding": "xudp"
            }
            if flow: outbound["flow"] = flow

            if security in ("tls", "reality", "xtls"):
                tls = {
                    "enabled": True, "server_name": sni,
                    "utls": {"enabled": True, "fingerprint": fp}
                }
                if security == "reality":
                    reality = {"enabled": True, "public_key": pbk}
                    if sid: reality["short_id"] = sid
                    tls["reality"] = reality
                outbound["tls"] = tls

            if network == "ws":
                path        = params.get("path", ["/"])[0]
                host_header = params.get("host", [host])[0]
                outbound["transport"] = {
                    "type": "ws", "path": path,
                    "headers": {"Host": host_header}}
            elif network == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": params.get("serviceName", [""])[0]}
            elif network == "http":
                outbound["transport"] = {"type": "http"}

            sec_label = security.upper() if security != "none" else "no TLS"
            if security == "reality":
                sec_label = "REALITY"
            summary = {
                "protocol": f"VLESS · {sec_label}",
                "server": f"{host}:{port}",
                "sni": sni,
                "flow": flow or "—",
                "network": network.upper()
            }
            return outbound, summary
        except Exception as e:
            return None, f"Parse error: {e}"

    return None, "Unsupported scheme. Use hysteria2:// or vless://"


def wrap_outbound(outbound: dict, routing: str = "Rule") -> dict:
    """
    Save only the proxy outbound. Everything else (DNS, inbound, route) is
    regenerated by apply_routing_to_config() at connect time, using the
    current tunnel mode (MIXED or TUN) from settings.
    """
    return {
        "outbounds": [outbound,
            {"type": "direct", "tag": "direct"}]
    }


def _is_ipv4(s: str) -> bool:
    try:
        parts = s.split('.')
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def apply_routing_to_config(cfg: dict, routing: str, mode: str = "mixed") -> dict:
    """
    Template-based: take Hiddify's known-working config and substitute
    only the user's proxy outbound + server-direct route rule + ports.

    This avoids the ongoing whack-a-mole with sing-box version migrations.
    Hiddify ships a config that works → we use the same structure verbatim.

    mode: "mixed" (Hiddify-style, default) or "tun" (kernel-level, needs admin)
    """
    cfg = json.loads(json.dumps(cfg))

    proxy_ob = None
    for ob in cfg.get("outbounds", []):
        if ob.get("tag") == "proxy":
            proxy_ob = ob; break
    if not proxy_ob:
        return cfg

    # Strip legacy keys that might break new sing-box
    proxy_ob.pop("domain_strategy", None)
    # Rename tag so it integrates with the select outbound below
    proxy_ob = dict(proxy_ob)
    proxy_ob["tag"] = "proxy"

    server = proxy_ob.get("server", "")

    # Server-direct routing rule (prevents TUN/proxy loop on VPN server IP)
    server_rule = None
    if server and _is_ipv4(server):
        server_rule = {"ip_cidr": [f"{server}/32"], "outbound": "direct"}
    elif server:
        server_rule = {"domain": [server], "outbound": "direct"}

    # Build inbound by mode
    if mode == "tun":
        inbound = {
            "type": "tun",
            "address": ["172.19.0.1/30"],
            "auto_route": True,
            "strict_route": False,
            "stack": "system",
            "mtu": 9000,                      # higher MTU reduces fragmentation issues
            "interface_name": "notevil-tun",
            "auto_redirect": False,
            # Exclude common private subnets from being routed through tunnel
            # This prevents the loop where DNS to 8.8.8.8 goes through TUN → proxy → needs DNS
            "route_exclude_address": [
                "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                "192.168.0.0/16", "169.254.0.0/16"
            ]
        }
    else:
        inbound = {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": MIXED_PROXY_PORT,
            "set_system_proxy": True
        }

    # ── Build base route rules ──
    base_rules = [
        {"action": "sniff"},
    ]
    # TUN mode needs explicit DNS handling — system DNS doesn't work
    # because all traffic (including DNS queries) goes through the tunnel.
    if mode == "tun":
        base_rules.append({"action": "hijack-dns", "protocol": "dns"})
    if server_rule:
        base_rules.append(server_rule)
    if routing == "Rule":
        base_rules.append({"ip_is_private": True, "outbound": "direct"})

    final_outbound = "direct" if routing == "Direct" else "proxy"

    # ── Pin SNI / server hostname to direct DNS (avoid resolver loops in TUN mode) ──
    sni = proxy_ob.get("tls", {}).get("server_name", "")
    pin = []
    if sni and not _is_ipv4(sni): pin.append(sni)
    if server and not _is_ipv4(server): pin.append(server)

    template = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [inbound],
        "outbounds": [
            proxy_ob,
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "rules": base_rules,
            "final": final_outbound,
            "auto_detect_interface": True
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{CLASH_API_PORT}",
                "secret": CLASH_API_SECRET,
                "store_fakeip": False
            }
        }
    }

    # ── DNS block: only needed for TUN mode ──
    if mode == "tun":
        dns_servers = [
            # Direct UDP DNS to 1.1.1.1 — for resolving the proxy server hostname/SNI
            # Goes through `direct` outbound (bypasses tunnel)
            {
                "tag": "dns-direct",
                "type": "udp",
                "server": "1.1.1.1"
            },
            # Remote DNS to 1.1.1.1 — for everything else, goes through proxy.
            # Use plain UDP (not HTTPS) — DoH needs to resolve cloudflare-dns.com
            # first which creates a chicken-and-egg problem.
            {
                "tag": "dns-remote",
                "type": "udp",
                "server": "1.1.1.1",
                "detour": "proxy"
            }
        ]
        dns_rules = []
        if pin:
            dns_rules.append({"domain": list(set(pin)), "server": "dns-direct"})
        template["dns"] = {
            "servers": dns_servers,
            "rules": dns_rules,
            "final": "dns-remote",
            "independent_cache": True
        }
        template["route"]["default_domain_resolver"] = "dns-direct"

    return template


# ─────────────────────────────────────────────
#  PROCESS / INTERFACE CLEANUP (zombie singbox, stale TUN, port bind)
# ─────────────────────────────────────────────
def cleanup_singbox_resources():
    """
    Kill any zombie sing-box.exe processes, remove stale TUN adapter,
    disable system proxy. Called before each sing-box launch to ensure
    fresh state — prevents 'port 9090 already in use' and 'TUN already exists'.
    """
    # 1. Kill zombie sing-box.exe processes
    killed = 0
    try:
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.info['name'] == 'sing-box.exe':
                    proc.kill()
                    killed += 1
            except Exception:
                pass
        if killed:
            log.info(f"Cleanup: killed {killed} zombie sing-box.exe processes")
    except Exception as e:
        log.error(f"Cleanup zombie kill: {e}")

    # 2. Remove stale TUN interface if it exists
    try:
        result = subprocess.run(
            ['netsh', 'interface', 'show', 'interface', 'notevil-tun'],
            capture_output=True, text=True, timeout=5,
            creationflags=0x08000000
        )
        if 'notevil-tun' in result.stdout:
            subprocess.run(
                ['netsh', 'interface', 'delete', 'interface', 'notevil-tun'],
                capture_output=True, timeout=5, creationflags=0x08000000
            )
            log.info("Cleanup: removed stale notevil-tun interface")
    except Exception as e:
        log.error(f"Cleanup TUN: {e}")

    # 3. Disable system proxy (sing-box MIXED mode may leave it enabled)
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    except Exception as e:
        log.error(f"Cleanup system proxy: {e}")

    # 4. Wait for port 9090 to become available (Windows TIME_WAIT can be 2 min,
    # but if process is killed it usually frees within 1-2s)
    import socket
    for attempt in range(20):  # max 2s
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", CLASH_API_PORT))
                # If bind succeeded, port is free
                return
        except OSError:
            time.sleep(0.1)
    log.warning(f"Port {CLASH_API_PORT} still busy after 2s wait")


# ─────────────────────────────────────────────
#  PING
# ─────────────────────────────────────────────
def tcp_ping(host: str, port: int, timeout: float = 2.5) -> int:
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return int((time.perf_counter() - t0) * 1000)
    except Exception:
        return -1


def server_from_profile(name: str):
    try:
        with open(os.path.join(PROFILES_DIR, name), "r", encoding="utf-8") as f:
            cfg = json.load(f)
        for ob in cfg.get("outbounds", []):
            if ob.get("tag") == "proxy":
                return ob.get("server", ""), ob.get("server_port", 443)
    except Exception:
        pass
    return None, None


# ─────────────────────────────────────────────
#  HISTORY
# ─────────────────────────────────────────────
def load_history():
    try:
        if os.path.exists(HISTORY_JSON):
            with open(HISTORY_JSON, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        log.error(f"load_history: {e}")
    return []

def save_history_entry(entry):
    try:
        hist = load_history()
        hist.insert(0, entry)
        hist = hist[:HISTORY_LIMIT]
        with open(HISTORY_JSON, 'w', encoding='utf-8') as f:
            json.dump(hist, f, ensure_ascii=False)
    except Exception as e:
        log.error(f"save_history: {e}")


# ─────────────────────────────────────────────
#  TAGS  (profile -> tag mapping)
# ─────────────────────────────────────────────
def load_tags() -> dict:
    try:
        if os.path.exists(TAGS_JSON):
            with open(TAGS_JSON, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        log.error(f"load_tags: {e}")
    return {}

def save_tags(data: dict):
    try:
        os.makedirs(os.path.dirname(TAGS_JSON), exist_ok=True)
        with open(TAGS_JSON, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception as e:
        log.error(f"save_tags: {e}")


# ─────────────────────────────────────────────
#  WORKERS
# ─────────────────────────────────────────────
class LogWorker(QThread):
    log_signal = pyqtSignal(str)
    died_signal = pyqtSignal()  # process died unexpectedly

    # Noise patterns: harmless connection-reset messages from sing-box that
    # clutter the log but indicate no real problem (browsers close idle
    # connections abruptly all the time).
    _NOISE = re.compile(
        r'connection upload closed'
        r'|forcibly closed by the remote host'
        r'|established connection was aborted by the software'
        r'|raw-read tcp 127\.0\.0\.1'
    )

    def __init__(self, process):
        super().__init__()
        self.process = process
        self._running = True
        self._re = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def stop(self):
        self._running = False

    def _drain_stdout(self):
        """Read everything left in stdout. Critical for capturing FATAL errors
        from sing-box when it dies within milliseconds of startup."""
        try:
            for line in self.process.stdout:
                if line:
                    clean = self._re.sub('', line.strip())
                    if not self._NOISE.search(clean):
                        self.log_signal.emit(clean)
        except Exception:
            pass

    def run(self):
        while self._running:
            if self.process.poll() is not None:
                # Process died — drain any remaining output BEFORE signaling death
                self._drain_stdout()
                if self._running:
                    self.died_signal.emit()
                break
            try:
                line = self.process.stdout.readline()
                if line:
                    clean = self._re.sub('', line.strip())
                    if not self._NOISE.search(clean):
                        self.log_signal.emit(clean)
                else:
                    time.sleep(0.05)
            except Exception:
                self._drain_stdout()
                break


class PingWorker(QThread):
    result = pyqtSignal(str, int)

    def __init__(self, profiles):
        super().__init__()
        self.profiles = profiles
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        for p in self.profiles:
            if not self._running: break
            host, port = server_from_profile(p)
            ms = tcp_ping(host, port) if host else -1
            if self._running:
                self.result.emit(p, ms)


class StatsWorker(QThread):
    stats_signal = pyqtSignal(int, int)

    def __init__(self):
        super().__init__()
        self._running = True
        self._sock = None

    def stop(self):
        self._running = False
        try:
            if self._sock: self._sock.close()
        except: pass

    def run(self):
        import http.client
        time.sleep(2)
        while self._running:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", CLASH_API_PORT, timeout=8)
                conn.request("GET", "/traffic",
                             headers={"Authorization": f"Bearer {CLASH_API_SECRET}"})
                resp = conn.getresponse()
                self._sock = conn.sock
                if resp.status == 200:
                    buf = b""
                    while self._running:
                        try: chunk = resp.read(1)
                        except Exception: break
                        if not chunk: break
                        buf += chunk
                        if buf.endswith(b"\n"):
                            line = buf.strip()
                            buf = b""
                            if line:
                                try:
                                    data = json.loads(line)
                                    self.stats_signal.emit(
                                        int(data.get("up", 0)),
                                        int(data.get("down", 0)))
                                except: pass
                try: conn.close()
                except: pass
            except Exception:
                pass
            if self._running:
                time.sleep(2)


class HealthCheckWorker(QThread):
    """Pings external host every N seconds to verify VPN actually works."""
    health_signal = pyqtSignal(bool, int)  # ok, latency_ms

    def __init__(self):
        super().__init__()
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        time.sleep(5)
        while self._running:
            ms = tcp_ping(HEALTH_CHECK_HOST, HEALTH_CHECK_PORT, timeout=3)
            if self._running:
                self.health_signal.emit(ms >= 0, ms if ms >= 0 else 0)
            for _ in range(HEALTH_CHECK_INTERVAL):
                if not self._running: break
                time.sleep(1)


# ─────────────────────────────────────────────
#  BRIDGE
# ─────────────────────────────────────────────
class Bridge(QThread):
    show_notification = pyqtSignal(str, str, str)  # title, body, level

    def __init__(self, parent=None):
        super().__init__(parent)
        self.sing_box_process = None
        self.log_worker = None
        self.ping_worker = None
        self.stats_worker = None
        self.health_worker = None
        self._page = None
        self._tmp_cfg = None
        self._current_profile = None
        self._current_routing = "Rule"
        self._session_start = None
        self._session_down = 0
        self._session_up = 0
        self._health_fails = 0
        self._auto_reconnect = True
        self._reconnect_attempts = 0
        self._max_reconnects = 3
        # For mini-mode state sync:
        self._status = "disconnected"   # disconnected | connecting | connected | unhealthy
        self._last_up_rate = 0
        self._last_down_rate = 0
        # Callbacks set by main window:
        self._mini_expand_cb = None
        self._mini_close_cb = None
        self._mini_show_cb = None
        self._win_minimize_cb = None
        self._win_close_cb = None
        self._win_drag_cb = None
        self._mini_drag_cb = None

    def set_web_page(self, page): self._page = page

    def js(self, code: str):
        if self._page: self._page.runJavaScript(code)

    # ── profiles ──
    @pyqtSlot(result=list)
    def get_profiles(self):
        if not os.path.exists(PROFILES_DIR): return []
        return sorted(f for f in os.listdir(PROFILES_DIR) if f.endswith('.json'))

    @pyqtSlot(str, result=str)
    def preview_key(self, key: str) -> str:
        """Return JSON summary of parsed key for preview (no save)."""
        outbound, result = parse_key(key)
        if outbound is None:
            return json.dumps({"ok": False, "error": result})
        return json.dumps({"ok": True, "summary": result})

    @pyqtSlot(str, str, str, result=str)
    def add_server_key(self, key: str, name: str, routing: str) -> str:
        name = re.sub(r'[^\w\-]', '_', name.strip() or "server")
        outbound, result = parse_key(key.strip())
        if outbound is None:
            return f"ERROR: {result}"
        cfg = wrap_outbound(outbound, routing or "Rule")
        filename = name + ".json"
        with open(os.path.join(PROFILES_DIR, filename), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        log.info(f"Profile saved: {filename}")
        return "OK:" + filename

    @pyqtSlot(str, str, result=str)
    def add_bulk_keys(self, text: str, routing: str) -> str:
        """Parse multiple keys (one per line). Returns JSON {added, skipped, errors}"""
        lines = [l.strip() for l in text.split('\n') if l.strip()]
        added = []
        errors = []
        for i, line in enumerate(lines):
            outbound, result = parse_key(line)
            if outbound is None:
                errors.append(f"Line {i+1}: {result}")
                continue
            # generate name from server+port
            srv = outbound.get("server", "unknown")
            prt = outbound.get("server_port", 0)
            base_name = f"{srv.replace('.', '_')}_{prt}"
            name = base_name
            n = 1
            while os.path.exists(os.path.join(PROFILES_DIR, name + ".json")):
                n += 1
                name = f"{base_name}_{n}"
            cfg = wrap_outbound(outbound, routing or "Rule")
            with open(os.path.join(PROFILES_DIR, name + ".json"), "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            added.append(name + ".json")
        log.info(f"Bulk import: {len(added)} added, {len(errors)} errors")
        return json.dumps({"added": added, "errors": errors})

    @pyqtSlot(str, str, result=str)
    def rename_profile(self, old_name: str, new_name: str) -> str:
        new_name = re.sub(r'[^\w\-]', '_', new_name.strip())
        if not new_name: return "ERROR: empty name"
        old_path = os.path.join(PROFILES_DIR, old_name)
        new_path = os.path.join(PROFILES_DIR, new_name + ".json")
        if os.path.exists(new_path):
            return "ERROR: profile with this name exists"
        try:
            os.rename(old_path, new_path)
            # carry over tag
            tags = load_tags()
            if old_name in tags:
                tags[new_name + ".json"] = tags.pop(old_name)
                save_tags(tags)
            log.info(f"Renamed: {old_name} → {new_name}.json")
            return "OK:" + new_name + ".json"
        except Exception as e:
            return f"ERROR:{e}"

    @pyqtSlot(str, result=str)
    def delete_profile(self, name: str) -> str:
        try:
            os.remove(os.path.join(PROFILES_DIR, name))
            # also remove its tag
            tags = load_tags()
            if name in tags:
                tags.pop(name)
                save_tags(tags)
            log.info(f"Deleted: {name}")
            return "OK"
        except Exception as e:
            return f"ERROR:{e}"

    @pyqtSlot(str, result=str)
    def get_profile_text(self, name: str) -> str:
        try:
            path = os.path.join(PROFILES_DIR, name)
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            return f"ERROR:{e}"

    @pyqtSlot(str, str, result=str)
    def set_profile_text(self, name: str, text: str) -> str:
        try:
            json.loads(text)
            path = os.path.join(PROFILES_DIR, name)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)
            log.info(f"Profile edited: {name}")
            return "OK"
        except json.JSONDecodeError as e:
            return f"Invalid JSON: {e}"
        except Exception as e:
            return f"ERROR:{e}"

    @pyqtSlot(str, result=str)
    def export_profiles(self, zip_path: str) -> str:
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                count = 0
                for f in os.listdir(PROFILES_DIR):
                    if f.endswith('.json'):
                        zf.write(os.path.join(PROFILES_DIR, f), arcname=f)
                        count += 1
            log.info(f"Exported {count} profiles to {zip_path}")
            return f"OK:{count}"
        except Exception as e:
            return f"ERROR:{e}"

    @pyqtSlot(str, result=str)
    def import_profiles(self, zip_path: str) -> str:
        try:
            count = 0
            skipped = 0
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for name in zf.namelist():
                    if not name.endswith('.json'): continue
                    safe = os.path.basename(name)
                    target = os.path.join(PROFILES_DIR, safe)
                    if os.path.exists(target):
                        skipped += 1
                        continue
                    with zf.open(name) as src, open(target, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                    count += 1
            log.info(f"Imported {count} profiles, {skipped} skipped")
            return json.dumps({"added": count, "skipped": skipped})
        except Exception as e:
            return f"ERROR:{e}"

    # ── ping ──
    @pyqtSlot()
    def ping_all(self):
        if self.ping_worker:
            self.ping_worker.stop()
            self.ping_worker.wait(500)
        profiles = self.get_profiles()
        if not profiles: return
        self.ping_worker = PingWorker(profiles)
        self.ping_worker.result.connect(
            lambda n, ms: self.js(f"pingResult({json.dumps(n)},{ms});"))
        self.ping_worker.start()

    # ── settings ──
    @pyqtSlot(result=str)
    def load_settings(self) -> str:
        try:
            if os.path.exists(SETTINGS_JSON):
                with open(SETTINGS_JSON, 'r', encoding='utf-8') as f:
                    return f.read()
        except: pass
        return '{}'

    @pyqtSlot(str)
    def save_settings(self, data: str):
        os.makedirs(os.path.dirname(SETTINGS_JSON), exist_ok=True)
        with open(SETTINGS_JSON, 'w', encoding='utf-8') as f:
            f.write(data)

    @pyqtSlot(result=str)
    def get_last_profile(self) -> str:
        try:
            if os.path.exists(SETTINGS_JSON):
                with open(SETTINGS_JSON, 'r') as f:
                    return json.load(f).get('last_profile', '')
        except: pass
        return ''

    def _save_last_profile(self, name: str):
        try:
            s = {}
            if os.path.exists(SETTINGS_JSON):
                with open(SETTINGS_JSON) as f: s = json.load(f)
            s['last_profile'] = name
            with open(SETTINGS_JSON, 'w') as f: json.dump(s, f)
        except: pass

    # ── autostart ──
    @pyqtSlot(result=bool)
    def get_autostart(self) -> bool:
        return autostart_enabled()

    @pyqtSlot(bool, result=bool)
    def set_autostart(self, enabled: bool) -> bool:
        ok = set_autostart(enabled)
        log.info(f"Autostart: {enabled} (ok={ok})")
        return ok

    # ── history ──
    @pyqtSlot(result=str)
    def get_history(self) -> str:
        return json.dumps(load_history())

    @pyqtSlot()
    def clear_history(self):
        try:
            if os.path.exists(HISTORY_JSON):
                os.remove(HISTORY_JSON)
        except: pass

    @pyqtSlot(str)
    def open_browser(self, url: str):
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception as e:
            log(f"open_browser error: {e}")

    # ── tags ──
    @pyqtSlot(result=str)
    def get_tags(self) -> str:
        return json.dumps(load_tags())

    @pyqtSlot(str, str, result=str)
    def set_profile_tag(self, profile: str, tag: str) -> str:
        try:
            tags = load_tags()
            tag = tag.strip()
            if tag:
                tags[profile] = tag
            else:
                tags.pop(profile, None)
            save_tags(tags)
            return "OK"
        except Exception as e:
            return f"ERROR:{e}"

    @pyqtSlot(result=str)
    def get_unique_tags(self) -> str:
        tags = load_tags()
        unique = sorted(set(v for v in tags.values() if v))
        return json.dumps(unique)

    # ── Mini-mode bridge ──
    @pyqtSlot(result=str)
    def mini_get_state(self) -> str:
        def fmt_rate(b):
            if b < 1024: return f"{b} B/s"
            if b < 1048576: return f"{b/1024:.1f} KB/s"
            return f"{b/1048576:.2f} MB/s"
        # Read current theme from settings on every poll so mini stays in sync
        theme = "green"
        custom_accent = "#39ff14"
        try:
            if os.path.exists(SETTINGS_JSON):
                with open(SETTINGS_JSON, 'r', encoding='utf-8') as f:
                    s = json.load(f)
                    theme = s.get('theme', 'green')
                    custom_accent = s.get('custom_accent', '#39ff14')
        except Exception:
            pass
        return json.dumps({
            "status": self._status,
            "profile": self._current_profile or "",
            "session_start": int(self._session_start) if self._session_start else None,
            "up_rate": fmt_rate(self._last_up_rate),
            "down_rate": fmt_rate(self._last_down_rate),
            "theme": theme,
            "custom_accent": custom_accent,
        })

    @pyqtSlot()
    def mini_toggle_vpn(self):
        if self._status in ("connected", "unhealthy", "connecting"):
            self.stop_connection()
        else:
            # use last profile
            last = self.get_last_profile()
            if last:
                # read current routing from settings
                try:
                    with open(SETTINGS_JSON) as f: s = json.load(f)
                    routing = s.get('routing', 'Rule')
                except: routing = 'Rule'
                self.start_connection(last, routing)

    @pyqtSlot()
    def mini_expand(self):
        if self._mini_expand_cb:
            self._mini_expand_cb()

    @pyqtSlot()
    def mini_close(self):
        if self._mini_close_cb:
            self._mini_close_cb()

    @pyqtSlot()
    def show_mini(self):
        # called by main UI; main window provides callback
        if self._mini_show_cb:
            self._mini_show_cb()

    # ── titlebar (custom frame controls) ──
    @pyqtSlot()
    def win_minimize(self):
        if self._win_minimize_cb: self._win_minimize_cb()

    @pyqtSlot()
    def win_close(self):
        if self._win_close_cb: self._win_close_cb()

    @pyqtSlot()
    def win_start_drag(self):
        if self._win_drag_cb: self._win_drag_cb()

    @pyqtSlot()
    def mini_start_drag(self):
        cb = getattr(self, "_mini_drag_cb", None)
        if cb: cb()

    # ── VPN ──
    @pyqtSlot(str, str)
    def start_connection(self, profile: str, routing: str):
        if not profile:
            self.js("addLog('> ERROR: no profile selected');"); return

        self._cleanup_workers()
        self._current_profile = profile
        self._current_routing = routing
        self._session_start = time.time()
        self._session_down = 0
        self._session_up = 0
        self._health_fails = 0
        self._reconnect_attempts = 0

        self._do_start_singbox(profile, routing)

    def _do_start_singbox(self, profile: str, routing: str):
        if not profile:
            # auto-reconnect may pass None if last profile got cleared
            log.warning("_do_start_singbox called with empty profile, aborting")
            self.js("addLog('> ERROR: no active profile for reconnect');")
            self._status = "disconnected"
            self.js("setStatus('disconnected');")
            return
        if not routing:
            routing = "Rule"
        self._status = "connecting"
        self.js(f"addLog({json.dumps('> ENGINE: NOTEVIL//NET ' + APP_VERSION)});")
        self.js(f"addLog({json.dumps('> INITIALIZING: ' + str(profile))});")
        self.js("setStatus('connecting');")

        # Clean up any zombies / stale TUN / occupied port before launching fresh sing-box
        try:
            cleanup_singbox_resources()
        except Exception as e:
            log.error(f"cleanup_singbox_resources: {e}")
        try:
            with open(os.path.join(PROFILES_DIR, profile), "r", encoding="utf-8") as f:
                original_cfg = json.load(f)
            # Read tunnel_mode from settings (default: mixed)
            tunnel_mode = "mixed"
            try:
                if os.path.exists(SETTINGS_JSON):
                    with open(SETTINGS_JSON, "r", encoding="utf-8") as sf:
                        tunnel_mode = json.load(sf).get("tunnel_mode", "mixed")
            except Exception:
                pass
            patched = apply_routing_to_config(original_cfg, routing, tunnel_mode)

            tmp_dir = os.path.join(BASE_DIR, "config", "tmp")
            os.makedirs(tmp_dir, exist_ok=True)
            self._tmp_cfg = os.path.join(tmp_dir, "active.json")
            with open(self._tmp_cfg, "w", encoding="utf-8") as f:
                json.dump(patched, f, indent=2)

            self.sing_box_process = subprocess.Popen(
                [CORE_EXE, "run", "-c", self._tmp_cfg],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', creationflags=0x08000000)

            # Also tee sing-box output to dedicated log file for debugging.
            # Use append mode so auto-reconnect attempts within one session
            # don't wipe FATAL errors from earlier crashes.
            self._singbox_log_path = os.path.join(LOGS_DIR, "sing-box.log")
            # Wipe only on the FIRST attempt of a fresh session
            fh_mode = "a" if self._reconnect_attempts > 0 else "w"
            try:
                self._singbox_log_fh = open(self._singbox_log_path, fh_mode, encoding="utf-8")
                self._singbox_log_fh.write(f"=== Session {datetime.now().isoformat()} · profile={profile} · routing={routing} · attempt={self._reconnect_attempts + 1} ===\n")
                self._singbox_log_fh.flush()
            except Exception:
                self._singbox_log_fh = None

            self.log_worker = LogWorker(self.sing_box_process)
            def _on_log_line(m):
                self.js(f"addLog({json.dumps('> ' + m)});")
                fh = getattr(self, "_singbox_log_fh", None)
                if fh:
                    try:
                        fh.write(m + "\n"); fh.flush()
                    except Exception:
                        pass
            self.log_worker.log_signal.connect(_on_log_line)
            self.log_worker.died_signal.connect(self._on_process_died)
            self.log_worker.start()
            self._save_last_profile(profile)

            QTimer.singleShot(2000, self._start_stats)
            QTimer.singleShot(3500, self._start_health_check)

            self._status = "connected"
            self.js("setStatus('connected');")
            self.js("addLog('> UPLINK ESTABLISHED');")
            self.js(f"addLog('> MODE: {tunnel_mode.upper()} · ROUTING: {routing}');")
            log.info(f"Connected: profile={profile}, mode={tunnel_mode}, routing={routing}")
            self.show_notification.emit(
                "VPN Connected", f"Profile: {profile.replace('.json','')}", "info")
        except Exception as e:
            log.error(f"start_connection: {e}")
            self._status = "disconnected"
            self.js(f"addLog({json.dumps('> ERROR: ' + str(e))});")
            self.js("setStatus('disconnected');")

    def _start_stats(self):
        if self.stats_worker:
            self.stats_worker.stop()
            self.stats_worker.wait(500)
        self.stats_worker = StatsWorker()
        self.stats_worker.stats_signal.connect(self._on_stats)
        self.stats_worker.start()

    def _on_stats(self, up: int, down: int):
        self._session_up += up
        self._session_down += down
        self._last_up_rate = up
        self._last_down_rate = down
        self.js(f"if(typeof updateStats==='function')updateStats({up},{down});")

    def _start_health_check(self):
        if self.health_worker:
            self.health_worker.stop()
            self.health_worker.wait(500)
        self.health_worker = HealthCheckWorker()
        self.health_worker.health_signal.connect(self._on_health)
        self.health_worker.start()

    def _on_health(self, ok: bool, ms: int):
        if ok:
            self._health_fails = 0
            if self._status == "unhealthy":
                self._status = "connected"
            self.js(f"if(typeof healthOk==='function')healthOk({ms});")
        else:
            self._health_fails += 1
            self.js(f"healthFail({self._health_fails});")
            log.warning(f"Health check failed ({self._health_fails}/{HEALTH_CHECK_FAILS_BEFORE_ALERT})")
            if self._health_fails >= HEALTH_CHECK_FAILS_BEFORE_ALERT and self._status == "connected":
                self._status = "unhealthy"
            if self._health_fails == HEALTH_CHECK_FAILS_BEFORE_ALERT:
                self.show_notification.emit(
                    "VPN Unhealthy",
                    "Cannot reach internet through tunnel. Check connection.",
                    "warning")

    def _on_process_died(self):
        log.warning("sing-box process died unexpectedly")
        self.js("addLog('> [!] CORE PROCESS DIED');")

        if (self._auto_reconnect and self._current_profile
            and self._reconnect_attempts < self._max_reconnects):
            self._reconnect_attempts += 1
            # Exponential backoff: 3s → 10s → 30s
            delays_ms = [3000, 10000, 30000]
            delay_ms = delays_ms[min(self._reconnect_attempts - 1, len(delays_ms) - 1)]
            delay_s = delay_ms // 1000
            self.js(f"addLog('> AUTO-RECONNECT attempt {self._reconnect_attempts}/{self._max_reconnects} in {delay_s}s...');")
            self.show_notification.emit(
                "VPN Reconnecting",
                f"Core died. Attempt {self._reconnect_attempts}/{self._max_reconnects} in {delay_s}s",
                "warning")
            QTimer.singleShot(delay_ms,
                lambda: self._do_start_singbox(self._current_profile, self._current_routing))
        else:
            self.js("addLog('> AUTO-RECONNECT GAVE UP');")
            self.show_notification.emit(
                "VPN Disconnected",
                "Auto-reconnect failed after several attempts.", "error")
            self._finalize_disconnect()

    def _cleanup_workers(self):
        for w in (self.stats_worker, self.log_worker, self.health_worker):
            if w:
                try:
                    w.stop()
                    w.wait(500)
                except: pass
        self.stats_worker = None
        self.log_worker = None
        self.health_worker = None

    def _finalize_disconnect(self):
        # Save to history
        if self._session_start and self._current_profile:
            duration = int(time.time() - self._session_start)
            save_history_entry({
                "profile": self._current_profile,
                "routing": self._current_routing,
                "start": int(self._session_start),
                "duration": duration,
                "down": self._session_down,
                "up": self._session_up
            })
        self._current_profile = None
        self._session_start = None
        self._status = "disconnected"
        self._last_up_rate = 0
        self._last_down_rate = 0
        self.js("setStatus('disconnected');")

    @pyqtSlot()
    def stop_connection(self):
        self._auto_reconnect_was = self._auto_reconnect
        self._auto_reconnect = False  # prevent reconnect on intentional stop

        self._cleanup_workers()
        if self.sing_box_process:
            try: self.sing_box_process.terminate()
            except: pass
            try: self.sing_box_process.wait(timeout=2)
            except: pass
        self.sing_box_process = None

        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'] == 'sing-box.exe':
                    proc.kill()
            except: pass

        # Give log worker a moment to drain any final stdout before we close fh
        worker = getattr(self, "log_worker", None)
        if worker:
            try: worker.wait(500)  # max 500ms
            except: pass

        # Full cleanup: remove TUN interface, disable system proxy, free port
        try:
            cleanup_singbox_resources()
        except Exception as e:
            log.error(f"stop cleanup: {e}")

        # Remove tmp/active.json (contains credentials)
        if self._tmp_cfg and os.path.exists(self._tmp_cfg):
            try: os.remove(self._tmp_cfg)
            except: pass

        # close sing-box log file handle (keep file on disk for inspection)
        fh = getattr(self, "_singbox_log_fh", None)
        if fh:
            try: fh.close()
            except: pass
            self._singbox_log_fh = None

        self.js("addLog('> UPLINK TERMINATED.');")
        log.info("Disconnected (user)")
        self.show_notification.emit("VPN Disconnected", "Connection ended.", "info")
        self._finalize_disconnect()

        self._auto_reconnect = True  # re-enable for next session


# ─────────────────────────────────────────────
#  HTML
# ─────────────────────────────────────────────
APP_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>not NETWORK</title>
<script src="qrc:///qtwebchannel/qwebchannel.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=DM+Mono:wght@300;400;500&display=swap');
:root {
  --accent: #2ae500; --accent-soft: rgba(42,229,0,.15); --accent-dim: rgba(42,229,0,.5);
  --bg: #080808; --bg2: #111111; --bg3: #161616; --bg4: #0a0a0a;
  --txt: #efffe3; --txt2: #baccb0; --txt3: rgba(186,204,176,.5); --txt4: rgba(186,204,176,.3);
  --border: rgba(60,75,53,.5); --border2: rgba(60,75,53,.25);
  --error: #ff6b6b; --warn: #f5c542;
  --sans: 'DM Sans', 'Segoe UI', system-ui, sans-serif;
  --mono: 'DM Mono', 'Cascadia Mono', 'Consolas', monospace;
  --display: 'DM Sans', 'Segoe UI', system-ui, sans-serif;
}
.theme-magenta {
  --accent: #ff2dd1; --accent-soft: rgba(255,45,209,.15); --accent-dim: rgba(255,45,209,.5);
  --bg: #080808; --bg2: #111111; --bg3: #161616; --bg4: #0a0a0a;
  --txt: #ffe3f7; --txt2: #ddb0d2;
  --border: rgba(110,30,90,.5); --border2: rgba(110,30,90,.25);
}
.theme-violet {
  --accent: #9d4dff; --accent-soft: rgba(157,77,255,.15); --accent-dim: rgba(157,77,255,.5);
  --bg: #080808; --bg2: #111111; --bg3: #161616; --bg4: #0a0a0a;
  --txt: #ebe3ff; --txt2: #c0b0dd;
  --border: rgba(70,50,130,.5); --border2: rgba(70,50,130,.25);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { background: transparent; color: var(--txt); font-family: var(--sans); -webkit-user-select: none; user-select: none; overflow: hidden; width: 100%; height: 100%; }
::-webkit-scrollbar { display: none; }
body { font-size: 14px; min-height: 100vh; }

/* iPhone-style rounded frame wrapping the whole app */
.app-frame {
  position: fixed; inset: 0;
  border-radius: 24px;
  background: rgba(6, 6, 6, 0.52);
  backdrop-filter: blur(28px) saturate(1.4);
  -webkit-backdrop-filter: blur(28px) saturate(1.4);
  overflow: hidden;
  border: 1px solid rgba(255,255,255,.1);
  transition: border-color .4s ease, box-shadow .6s ease;
  display: flex;
  flex-direction: column;
  height: 100%;
  width: 100%;
}
.app-frame.vpn-on {
  border-color: var(--accent);
  animation: framePulse 3.5s ease-in-out infinite;
}
@keyframes framePulse {
  0%, 100% { border-color: var(--accent-dim); }
  50% { border-color: var(--accent); }
}
.app-scroll {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  min-height: 0;
}

.card { background: rgba(10, 10, 10, 0.45); border: 1px solid rgba(255,255,255,.07); border-radius: 12px; backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); }

.topbar {
  position: relative; z-index: 100;
  background: rgba(6, 6, 6, 0.40);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-bottom: 1px solid rgba(255,255,255,.07);
  padding: 8px 6px 8px 18px; display: flex; justify-content: space-between; align-items: center;
  cursor: grab;
  flex-shrink: 0;
}
.topbar:active { cursor: grabbing; }
.topbar .logo { display: flex; align-items: center; gap: 8px; }
.topbar .logo-icon { width: 28px; height: 28px; flex-shrink: 0; display:flex; align-items:center; justify-content:center; }
.logo-icon img { width: 28px; height: 28px; object-fit: contain; display: block; }
.topbar .logo-icon svg { width: 100%; height: 100%; }
.topbar .logo-icon svg path { stroke: var(--accent); fill: none; stroke-width: 2; stroke-linejoin: round; }
.topbar .logo-text { font-family: var(--display); font-weight: 700; color: var(--accent); font-size: 15px; letter-spacing: -0.01em; }
.topbar .status-pill { display: flex; align-items: center; gap: 8px; font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 0.18em; text-transform: uppercase; color: var(--txt3); }
.topbar .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--txt3); transition: background .3s; }
.status-dot.online { background: var(--accent); animation: pulse 1.5s infinite; }
.status-dot.connecting { background: var(--warn); }
.status-dot.unhealthy { background: var(--warn); animation: pulse 1s infinite; }

.win-controls { display: flex; gap: 2px; }
.win-controls .wc-btn {
  background: none; border: none; cursor: pointer;
  color: var(--txt3); width: 28px; height: 26px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 5px; transition: all .15s; padding: 0;
}
.win-controls .wc-btn:hover { background: rgba(255,255,255,.08); color: var(--txt); }
.win-controls .wc-close:hover { background: rgba(255,49,49,.18); color: #ff6b6b; }
.win-controls .wc-btn svg { width: 12px; height: 12px; }

@keyframes pulse { 0%,100% { opacity: 1; box-shadow: 0 0 6px var(--accent); } 50% { opacity: 0.5; box-shadow: 0 0 1px var(--accent); } }
@keyframes slideUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

main { padding: 76px 20px 0; max-width: 480px; margin: 0 auto; }
.screen { display: none; }
.screen.active { display: block; animation: slideUp .25s ease; }
h2 { font-family: var(--display); font-size: 24px; font-weight: 700; letter-spacing: -0.01em; }
.section-label { display: flex; align-items: center; gap: 6px; font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 0.2em; text-transform: uppercase; color: var(--accent); margin-bottom: 4px; }

.status-card { padding: 22px; margin: 16px 0 14px; position: relative; overflow: hidden; border-top: 1px solid var(--accent-soft) !important; }
.laser-top {
  position: absolute; top: 0; left: -50%; right: -50%;
  height: 2px;
  background: linear-gradient(90deg,
    transparent 0%,
    transparent 40%,
    var(--accent-dim) 48%,
    var(--accent) 50%,
    var(--accent-dim) 52%,
    transparent 60%,
    transparent 100%);
  animation: laserSweep 2.8s ease-in-out infinite;
  filter: drop-shadow(0 0 6px var(--accent));
}
@keyframes laserSweep {
  0%   { transform: translateX(-50%); opacity: 0; }
  10%  { opacity: 1; }
  90%  { opacity: 1; }
  100% { transform: translateX(50%); opacity: 0; }
}
/* secondary glow line below */
.laser-top::after {
  content: '';
  position: absolute; left: 0; right: 0; top: 0;
  height: 1px;
  background: var(--accent);
  opacity: 0.15;
  box-shadow: 0 0 8px var(--accent);
}
.status-row { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 18px; }
.big-status-dot { width: 12px; height: 12px; border-radius: 50%; background: var(--txt3); margin-top: 4px; transition: all .3s; }
.big-status-dot.online { background: var(--accent); animation: pulse 1.5s infinite; }
.big-status-dot.connecting { background: var(--warn); }
.big-status-dot.unhealthy { background: var(--warn); animation: pulse 1s infinite; }
.status-text { font-family: var(--display); font-size: 20px; font-weight: 700; letter-spacing: -0.01em; }
.status-text.online { color: var(--accent); }
.status-text.connecting { color: var(--warn); }
.status-text.unhealthy { color: var(--warn); }
.kicker { font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: 0.2em; text-transform: uppercase; color: var(--txt4); margin-bottom: 2px; }

label.field-label { display: block; font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 0.15em; text-transform: uppercase; color: var(--txt3); margin-bottom: 8px; }
select, .input, textarea {
  width: 100%; background: rgba(8, 8, 8, 0.42) !important; border: 1px solid rgba(255,255,255,.09);
  color: var(--txt) !important; font-family: var(--mono); font-size: 12px;
  padding: 11px 14px; border-radius: 8px; outline: none;
  backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
  transition: border-color .2s, box-shadow .2s; color-scheme: dark;
}
select:focus, .input:focus, textarea:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
select { appearance: none; padding-right: 32px; cursor: pointer; }
select option { background: #0d0d0d; color: var(--txt); }
.select-wrap { position: relative; }
.select-wrap::after { content: '▾'; position: absolute; right: 14px; top: 50%; transform: translateY(-50%); color: var(--txt3); pointer-events: none; font-size: 10px; }
textarea { resize: none; }
::placeholder { color: var(--txt4); }

.btn-primary { width: 100%; background: var(--accent); color: var(--btn-txt, #052900); border: none; padding: 14px; border-radius: 10px; font-family: var(--mono); font-size: 11px; font-weight: 700; letter-spacing: 0.18em; cursor: pointer; transition: all .2s; }
.btn-primary:hover { box-shadow: 0 0 18px var(--accent-dim); }
.btn-primary.disabled { background: var(--accent-soft); color: var(--accent); cursor: default; }
.btn-danger { width: 100%; background: rgba(255,49,49,.12); color: #ff3131; border: 1px solid rgba(255,49,49,.35); padding: 14px; border-radius: 10px; font-family: var(--mono); font-size: 11px; font-weight: 700; letter-spacing: 0.18em; cursor: pointer; transition: all .2s; }
.btn-danger:hover { background: rgba(255,49,49,.22); }
.btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--accent); padding: 11px 16px; border-radius: 8px; font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 0.15em; cursor: pointer; text-transform: uppercase; transition: all .2s; display: inline-flex; align-items: center; gap: 6px; }
.btn-ghost:hover { border-color: var(--accent); background: var(--accent-soft); }
.btn-dash { width: 100%; background: transparent; border: 1.5px dashed var(--accent-dim); color: var(--accent); padding: 13px; border-radius: 10px; font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 0.18em; cursor: pointer; text-transform: uppercase; margin-bottom: 14px; transition: all .2s; display: flex; align-items: center; justify-content: center; gap: 8px; }
.btn-dash:hover { border-color: var(--accent); background: var(--accent-soft); }

.stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 14px; }
.stats-grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 14px; }
.stat-mini { padding: 12px; }
.stat-mini .lbl { font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: 0.18em; text-transform: uppercase; color: var(--txt4); margin-bottom: 4px; }
.stat-mini .val { font-family: var(--mono); font-size: 14px; font-weight: 700; color: var(--accent); }
.stat-big { padding: 14px; }
.stat-big .lbl { font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: 0.18em; text-transform: uppercase; color: var(--txt4); display: flex; justify-content: space-between; margin-bottom: 6px; }
.stat-big .val { font-family: var(--mono); font-size: 19px; font-weight: 700; color: var(--accent); }
.stat-big .sub { font-family: var(--mono); font-size: 10px; color: var(--accent-dim); margin-top: 3px; }

.terminal { overflow: hidden; margin-bottom: 12px; }
.terminal-hd { display: flex; align-items: center; gap: 8px; padding: 8px 14px; background: rgba(6,6,6,0.5); border-bottom: 1px solid rgba(255,255,255,.07); font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: 0.2em; text-transform: uppercase; color: var(--accent); }
.terminal-hd .clr-btn { margin-left: auto; background: none; border: none; font-family: var(--mono); font-size: 9px; font-weight: 700; color: var(--txt4); letter-spacing: 0.18em; cursor: pointer; }
.terminal-hd .clr-btn:hover { color: var(--txt2); }
#logOutput { height: 175px; padding: 14px; overflow-y: auto; font-family: var(--mono); font-size: 11px; line-height: 1.65; color: var(--accent); white-space: pre-wrap; }

.spark { display: flex; align-items: flex-end; gap: 2px; height: 48px; }
.spark .bar { flex: 1; min-height: 3px; background: var(--accent-soft); border-radius: 2px 2px 0 0; transition: height .4s; }
.spark .bar.hot { background: var(--accent); }

.node-row { background: rgba(10, 10, 10, 0.38); border: 1px solid rgba(255,255,255,.06); padding: 12px 14px; border-radius: 10px; display: flex; align-items: center; gap: 12px; margin-bottom: 8px; cursor: pointer; transition: all .2s; position: relative; backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); }
.node-row:hover { border-color: var(--accent-dim); }
.node-row.active { border-color: var(--accent); box-shadow: 0 0 12px var(--accent-soft); }
.node-row .status-circle { width: 10px; height: 10px; border-radius: 50%; background: var(--txt4); flex-shrink: 0; transition: all .3s; }
.node-row .status-circle.alive { background: var(--accent); box-shadow: 0 0 6px var(--accent); animation: pulse 1.6s infinite; }
.node-row .status-circle.dead { background: var(--error); opacity: 0.5; }
.node-row .name { flex: 1; min-width: 0; }
.node-row .name .title { font-size: 14px; color: var(--txt); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.node-row .name .sub { font-family: var(--mono); font-size: 9px; color: var(--txt4); text-transform: uppercase; }
.ping-badge { font-family: var(--mono); font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 4px; letter-spacing: 0.05em; }
.ping-badge.good { color: var(--accent); background: var(--accent-soft); }
.ping-badge.mid { color: var(--warn); background: rgba(245,197,66,.12); }
.ping-badge.bad { color: var(--error); background: rgba(255,107,107,.1); }
.ping-badge.off { color: var(--txt4); background: rgba(60,75,53,.2); }
.ping-badge.wait { color: var(--txt4); }
.menu-btn { background: none; border: none; color: var(--txt3); cursor: pointer; padding: 6px 8px; border-radius: 6px; font-size: 16px; line-height: 1; transition: all .2s; letter-spacing: 1px; }
.menu-btn:hover { color: var(--accent); background: var(--accent-soft); }
.select-mark { width: 18px; height: 18px; border-radius: 50%; border: 1.5px solid var(--border); flex-shrink: 0; transition: all .2s; position: relative; }
.node-row.active .select-mark { border-color: var(--accent); background: var(--accent); box-shadow: 0 0 8px var(--accent-soft); }
.node-row.active .select-mark::after { content: ''; position: absolute; top: 4px; left: 4px; width: 8px; height: 8px; background: #080808; border-radius: 50%; }

/* Context menu (3-dots) */
.ctx-menu {
  position: fixed;
  z-index: 250;
  background: rgba(10,10,10,0.88); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--accent-dim);
  border-radius: 10px;
  min-width: 200px;
  padding: 6px;
  box-shadow: 0 8px 30px rgba(0,0,0,.5), 0 0 20px var(--accent-soft);
  animation: slideUp .15s ease;
}
.ctx-menu .item {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 12px;
  font-family: var(--sans);
  font-size: 13px;
  color: var(--txt);
  cursor: pointer;
  border-radius: 6px;
  transition: background .15s;
}
.ctx-menu .item:hover { background: var(--accent-soft); color: var(--accent); }
.ctx-menu .item.danger { color: var(--error); }
.ctx-menu .item.danger:hover { background: rgba(255,107,107,.1); color: var(--error); }
.ctx-menu .item .ic { font-size: 14px; width: 16px; text-align: center; }
.ctx-menu .divider { height: 1px; background: var(--border2); margin: 4px 6px; }

.search-wrap { position: relative; margin-bottom: 12px; }
.search-wrap .input { padding-left: 38px; }
.search-wrap::before { content: '🔍'; position: absolute; left: 13px; top: 50%; transform: translateY(-50%); font-size: 12px; opacity: .5; }

.settings-section { margin-bottom: 16px; }
.settings-section h3 { font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 0.2em; text-transform: uppercase; color: var(--txt4); margin-bottom: 8px; padding: 0 4px; }
.settings-list { background: rgba(10, 10, 10, 0.38); border: 1px solid rgba(255,255,255,.06); border-radius: 12px; overflow: hidden; backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); }
.settings-list .row { display: flex; align-items: center; justify-content: space-between; padding: 14px 16px; border-bottom: 1px solid var(--border2); }
.settings-list .row:last-child { border-bottom: none; }
.settings-list .row .left { display: flex; align-items: center; gap: 12px; }
.settings-list .row .ico { font-size: 20px; color: var(--accent); width: 24px; text-align: center; }
.settings-list .row .title { font-size: 14px; color: var(--txt); }
.settings-list .row .sub { font-family: var(--mono); font-size: 10px; color: var(--txt4); margin-top: 2px; }
.settings-list .row.clickable { cursor: pointer; }
.settings-list .row.clickable:hover { background: rgba(255,255,255,.02); }

.toggle { width: 40px; height: 22px; background: rgba(60,75,53,.4); border-radius: 999px; position: relative; cursor: pointer; border: 1px solid var(--border); transition: all .2s; flex-shrink: 0; }
.radio-dot { width: 18px; height: 18px; border-radius: 50%; border: 2px solid var(--border); flex-shrink: 0; position: relative; transition: all .15s; }
.radio-dot.on { border-color: var(--accent); }
.radio-dot.on::after { content: ""; position: absolute; inset: 3px; border-radius: 50%; background: var(--accent); }
.toggle.on { background: var(--accent-soft); border-color: var(--accent-dim); }
.toggle::after { content: ''; position: absolute; width: 16px; height: 16px; background: var(--txt3); border-radius: 50%; top: 2px; left: 2px; transition: all .2s; }
.toggle.on::after { left: 20px; background: var(--accent); box-shadow: 0 0 8px var(--accent); }

.routing-card { padding: 16px; }
.routing-pill-group { display: grid; grid-template-columns: repeat(3, 1fr); gap: 3px; padding: 3px; background: rgba(0,0,0,.3); border: 1px solid var(--border2); border-radius: 8px; }
.routing-pill { background: none; border: none; padding: 8px 0; font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--txt3); border-radius: 5px; cursor: pointer; transition: all .2s; }
.routing-pill.active { background: var(--accent); color: var(--btn-txt, #022100); box-shadow: 0 0 10px var(--accent-soft); }

.theme-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.theme-card { border: 1.5px solid var(--border); background: rgba(10,10,10,0.5); border-radius: 10px; padding: 12px 8px; cursor: pointer; text-align: center; transition: all .2s; }
.theme-card.active { border-color: var(--accent); box-shadow: 0 0 10px var(--accent-soft); }
.theme-card:hover:not(.active) { border-color: var(--accent-dim); }
.theme-swatch { width: 28px; height: 28px; border-radius: 50%; margin: 0 auto 6px; border: 1.5px solid rgba(255,255,255,.1); }
.theme-name { font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: 0.15em; text-transform: uppercase; color: var(--txt2); }
.theme-card.active .theme-name { color: var(--accent); }
.quick-color { width: 22px; height: 22px; border-radius: 50%; border: 1.5px solid rgba(255,255,255,.1); cursor: pointer; padding: 0; transition: transform .15s; }
.quick-color:hover { transform: scale(1.15); border-color: var(--accent); }
.theme-custom {
  --accent: var(--custom-accent, #39ff14);
  --accent-soft: var(--custom-soft, rgba(57,255,20,.15));
  --accent-dim: var(--custom-dim, rgba(57,255,20,.5));
  --txt: color-mix(in srgb, var(--custom-accent, #39ff14) 25%, #e8ffe8);
  --txt2: color-mix(in srgb, var(--custom-accent, #39ff14) 45%, rgba(180,200,180,.8));
  --txt3: color-mix(in srgb, var(--custom-accent, #39ff14) 30%, rgba(150,170,150,.5));
  --txt4: color-mix(in srgb, var(--custom-accent, #39ff14) 20%, rgba(120,140,120,.3));
  --border: color-mix(in srgb, var(--custom-accent, #39ff14) 15%, rgba(60,70,60,.5));
  --border2: color-mix(in srgb, var(--custom-accent, #39ff14) 10%, rgba(60,70,60,.25));
}

/* Tags */
.tag-filter-bar { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
.tag-pill {
  background: rgba(10,10,10,0.75); border: 1px solid rgba(255,255,255,.09); color: var(--txt2);
  padding: 5px 12px; border-radius: 999px; font-family: var(--mono);
  font-size: 10px; font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; cursor: pointer; transition: all .15s;
}
.tag-pill:hover { border-color: var(--accent-dim); color: var(--accent); }
.tag-pill.active { background: var(--accent); color: #052900; border-color: var(--accent); }
.tag-group-header {
  font-family: var(--mono); font-size: 10px; font-weight: 700;
  letter-spacing: 0.2em; text-transform: uppercase;
  color: var(--accent); margin: 14px 4px 6px;
  display: flex; align-items: center; gap: 8px;
}
.tag-group-header .tg-count {
  background: var(--accent-soft); color: var(--accent);
  padding: 2px 7px; border-radius: 10px; font-size: 9px;
  font-weight: 700; letter-spacing: 0;
}
.tag-chip {
  display: inline-block; padding: 1px 7px; margin-left: 4px;
  background: var(--accent-soft); color: var(--accent);
  border-radius: 4px; font-family: var(--mono); font-size: 9px;
  font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase;
  vertical-align: middle;
}

nav.bottom { position: relative; z-index: 100; display: flex; justify-content: space-around; align-items: center; background: rgba(8,8,8,0.55); border-top: 1px solid rgba(255,255,255,.07); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); height: 64px; flex-shrink: 0; }
nav.bottom button { background: none; border: none; cursor: pointer; display: flex; flex-direction: column; align-items: center; gap: 4px; color: var(--txt3); transition: color .2s; }
nav.bottom button .ico { font-size: 22px; }
nav.bottom button .lbl { font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; }
nav.bottom button:hover { color: var(--txt2); }
nav.bottom button.active { color: var(--accent); text-shadow: 0 0 8px var(--accent-soft); }

.modal-bg { position: fixed; inset: 0; z-index: 200; background: rgba(4,4,4,.65); backdrop-filter: blur(4px); -webkit-backdrop-filter: blur(4px); display: none; align-items: center; justify-content: center; padding: 20px; }
.modal-bg.show { display: flex; animation: slideUp .2s ease; }
.modal { background: rgba(8, 8, 8, 0.72); border: 1px solid var(--accent-dim); border-radius: 14px; width: 100%; max-width: 380px; padding: 22px; box-shadow: 0 0 40px var(--accent-soft); max-height: 80vh; overflow-y: auto; backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px); }
.modal-hd { display: flex; align-items: center; gap: 8px; margin-bottom: 18px; }
.modal-hd .title { font-family: var(--display); font-size: 18px; font-weight: 700; letter-spacing: -0.01em; }
.modal-hd .close-btn { margin-left: auto; background: none; border: none; cursor: pointer; color: var(--txt3); font-size: 22px; line-height: 1; }
.modal-hd .close-btn:hover { color: var(--txt); }
.modal-field { margin-bottom: 14px; }
.modal-error { font-family: var(--mono); font-size: 10px; color: var(--error); margin-bottom: 10px; }
.modal-actions { display: flex; gap: 8px; }
.modal-actions > * { flex: 1; }

.muted-sm { font-family: var(--mono); font-size: 9px; color: var(--txt4); margin-top: 6px; letter-spacing: 0.05em; }
.empty { text-align: center; padding: 36px 0; font-family: var(--mono); font-size: 11px; color: var(--txt4); letter-spacing: 0.15em; text-transform: uppercase; }

/* Mode toggle in add modal */
.mode-tabs { display: flex; gap: 4px; padding: 3px; background: rgba(8,8,8,0.4); border: 1px solid rgba(255,255,255,.07); border-radius: 8px; margin-bottom: 14px; }
.mode-tab { flex: 1; background: none; border: none; padding: 8px; font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--txt3); border-radius: 5px; cursor: pointer; transition: all .2s; }
.mode-tab.active { background: var(--accent); color: var(--btn-txt, #022100); }

/* Preview box */
.preview-box { background: rgba(8,8,8,0.4); border: 1px solid rgba(255,255,255,.07); border-radius: 8px; padding: 12px; margin-bottom: 14px; font-family: var(--mono); font-size: 11px; }
.preview-box.error { border-color: var(--error); }
.preview-box.ok { border-color: var(--accent-dim); }
.preview-row { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 4px; }
.preview-row:last-child { margin-bottom: 0; }
.preview-row .pk { color: var(--txt4); text-transform: uppercase; font-size: 9px; letter-spacing: 0.1em; }
.preview-row .pv { color: var(--accent); }

/* History list */
.hist-item { background: rgba(10,10,10,0.42); border: 1px solid rgba(255,255,255,.07); border-radius: 8px; padding: 12px 14px; margin-bottom: 8px; }
.hist-item .top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
.hist-item .name { font-size: 13px; color: var(--txt); }
.hist-item .date { font-family: var(--mono); font-size: 10px; color: var(--txt4); }
.hist-item .meta { display: flex; gap: 14px; font-family: var(--mono); font-size: 10px; color: var(--txt3); }
.hist-item .meta b { color: var(--accent); font-weight: 700; }
</style>
</head>
<body>

<div class="app-frame" id="appFrame">
<header class="topbar" onmousedown="onTitleDrag(event)">
  <div class="logo">
    <div class="logo-icon">
      <svg viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg" width="20" height="20">
        <!-- Signal bars icon -->
        <rect x="1"  y="13" width="3.5" height="5"  rx="0.8" fill="var(--accent)" opacity="0.4"/>
        <rect x="6"  y="9"  width="3.5" height="9"  rx="0.8" fill="var(--accent)" opacity="0.65"/>
        <rect x="11" y="5"  width="3.5" height="13" rx="0.8" fill="var(--accent)" opacity="0.85"/>
        <rect x="16" y="1"  width="3.5" height="17" rx="0.8" fill="var(--accent)"/>
      </svg>
    </div>
    <div class="logo-text">not NETWORK</div>
  </div>
  <div style="display:flex;align-items:center;gap:10px">
    <div class="win-controls">
      <button id="miniBtn" onclick="goMini()" title="Mini mode (Ctrl+Shift+M)" class="wc-btn" type="button">
        <svg viewBox="0 0 12 12"><rect x="2.5" y="6" width="7" height="3" stroke="currentColor" stroke-width="1.2" fill="none" rx="0.5"/></svg>
      </button>
      <button onclick="winMinimize()" title="Minimize" class="wc-btn" type="button">
        <svg viewBox="0 0 12 12"><line x1="2.5" y1="6" x2="9.5" y2="6" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>
      </button>
      <button onclick="winClose()" title="Close" class="wc-btn wc-close" type="button">
        <svg viewBox="0 0 12 12"><path d="M 3 3 L 9 9 M 9 3 L 3 9" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round"/></svg>
      </button>
    </div>
  </div>
</header>
<div class="app-scroll">

<main>

  <!-- HOME -->
  <div id="screen-home" class="screen active">
    <div class="card status-card">
      <div class="laser-top"></div>
      <div class="status-row">
        <div id="bigStatusDot" class="big-status-dot"></div>
        <div style="flex:1">
          <div class="kicker">VPN STATUS</div>
          <div id="bigStatusText" class="status-text">DISCONNECTED</div>
        </div>
        <div style="text-align:right">
          <div class="kicker">PROFILE</div>
          <div id="activeProfileLabel" style="font-family:var(--mono);font-size:11px;color:var(--accent);margin-top:2px">—</div>
        </div>
      </div>
      <div style="margin-bottom:14px">
        <label class="field-label">NETWORK PROFILE</label>
        <div class="select-wrap"><select id="profileSelect"></select></div>
      </div>
      <button id="connectBtn" class="btn-primary" onclick="handleConnect()">INITIALIZE UPLINK</button>
    </div>

    <div class="stats-grid">
      <div class="card stat-mini"><div class="lbl">LATENCY</div><div id="latencyVal" class="val">— ms</div></div>
      <div class="card stat-mini"><div class="lbl">↑ UPLOAD</div><div id="homeUpRate" class="val" style="color:#b7c8e1">0 B/s</div></div>
      <div class="card stat-mini"><div class="lbl">↓ DOWN</div><div id="homeDownRate" class="val">0 B/s</div></div>
    </div>

    <div class="card terminal">
      <div class="terminal-hd">
        <span>▶</span> SYSTEM LOG
        <span id="routingBadge" style="color:var(--txt4);margin-left:8px"></span>
        <button class="clr-btn" onclick="clearLog()">CLR</button>
      </div>
      <div id="logOutput"></div>
    </div>
  </div>

  <!-- SERVERS -->
  <div id="screen-servers" class="screen">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin:18px 0 14px;gap:10px">
      <div>
        <div class="section-label">▼ NODE_SELECTION</div>
        <h2>Server Nodes</h2>
      </div>
      <button class="btn-ghost" onclick="pingAll()" id="pingAllBtn">📡 PING ALL</button>
    </div>
    <div class="search-wrap">
      <input id="nodeSearch" class="input" oninput="filterNodes(this.value)" placeholder="SEARCH NODES..." />
    </div>
    <div id="tagFilterBar" class="tag-filter-bar"></div>
    <button class="btn-dash" onclick="openAddModal()">+ ADD SERVER VIA KEY</button>
    <div id="nodeList"></div>
  </div>

  <!-- STATS -->
  <div id="screen-stats" class="screen">
    <div style="margin:18px 0 16px">
      <div class="section-label">▼ NETWORK_DIAGNOSTICS</div>
      <h2>Traffic Statistics</h2>
      <p style="color:var(--txt3);font-size:13px;margin-top:4px">Real-time encrypted traffic via sing-box API.</p>
    </div>
    <div class="stats-grid-2">
      <div class="card stat-big" style="border-left:2px solid var(--accent)">
        <div class="lbl"><span>DOWNLOADED</span><span>↓</span></div>
        <div id="statDown" class="val">0.00 B</div>
        <div id="statDownRate" class="sub">0 B/s</div>
      </div>
      <div class="card stat-big" style="border-left:2px solid #b7c8e1">
        <div class="lbl"><span>UPLOADED</span><span>↑</span></div>
        <div id="statUp" class="val" style="color:#b7c8e1">0.00 B</div>
        <div id="statUpRate" class="sub" style="color:rgba(183,200,225,.5)">0 B/s</div>
      </div>
      <div class="card stat-big">
        <div class="lbl"><span>SESSION</span><span>⏱</span></div>
        <div id="sessionTime" class="val" style="color:var(--txt)">00:00:00</div>
      </div>
      <div class="card stat-big">
        <div class="lbl"><span>HEALTH</span><span>♥</span></div>
        <div id="healthStatus" class="val" style="color:var(--txt3)">—</div>
      </div>
    </div>
    <div class="card" style="padding:14px;margin-bottom:14px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <div style="display:flex;gap:14px;align-items:center">
          <div class="kicker" style="margin:0">Throughput · 60s</div>
          <div style="display:flex;gap:10px;font-family:var(--mono);font-size:9px">
            <span style="display:flex;align-items:center;gap:4px"><span style="width:8px;height:8px;background:var(--accent);border-radius:2px;display:inline-block"></span>DOWN</span>
            <span style="display:flex;align-items:center;gap:4px"><span style="width:8px;height:8px;background:#b7c8e1;border-radius:2px;display:inline-block"></span>UP</span>
          </div>
        </div>
        <div style="font-family:var(--mono);font-size:10px;color:var(--accent)">LIVE</div>
      </div>
      <canvas id="chartCanvas" width="600" height="140" style="width:100%;height:140px;display:block"></canvas>
    </div>

    <div style="margin-bottom:10px;display:flex;justify-content:space-between;align-items:center">
      <div class="kicker">Connection History</div>
      <button class="clr-btn" onclick="clearHistory()" style="background:none;border:none;font-family:var(--mono);font-size:9px;font-weight:700;color:var(--txt4);letter-spacing:0.18em;cursor:pointer;text-transform:uppercase">CLEAR</button>
    </div>
    <div id="historyList"></div>
  </div>

  <!-- SETTINGS -->
  <div id="screen-settings" class="screen">
    <div style="margin:18px 0 16px">
      <div class="section-label">▼ SYSTEM_CONFIG</div>
      <h2>Settings</h2>
    </div>

    <div class="settings-section">
      <h3>Appearance</h3>
      <div class="card" style="padding:14px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
          <span style="font-size:20px">🎨</span>
          <div style="font-size:14px">Text Color</div>
        </div>
        <div id="customPickerWrap" style="margin-top:0px">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
            <span style="font-size:12px;color:var(--txt2);font-family:var(--mono);letter-spacing:0.1em;text-transform:uppercase">Accent Color</span>
            <input type="color" id="customColorInput" value="#39ff14" style="width:50px;height:32px;border:1px solid var(--border);border-radius:6px;background:transparent;cursor:pointer;padding:2px" oninput="onCustomColorChange(this.value)"/>
            <input id="customHexInput" class="input" style="flex:1;font-size:11px;padding:8px 10px" value="#39ff14" oninput="onCustomHexInput(this.value)"/>
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            <button class="quick-color" style="background:#39ff14" onclick="onCustomColorChange('#39ff14')"></button>
            <button class="quick-color" style="background:#00ffff" onclick="onCustomColorChange('#00ffff')"></button>
            <button class="quick-color" style="background:#ffaa00" onclick="onCustomColorChange('#ffaa00')"></button>
            <button class="quick-color" style="background:#ff007a" onclick="onCustomColorChange('#ff007a')"></button>
            <button class="quick-color" style="background:#bf00ff" onclick="onCustomColorChange('#bf00ff')"></button>
            <button class="quick-color" style="background:#ff6b35" onclick="onCustomColorChange('#ff6b35')"></button>
            <button class="quick-color" style="background:#ffe600" onclick="onCustomColorChange('#ffe600')"></button>
            <button class="quick-color" style="background:#7cffcb" onclick="onCustomColorChange('#7cffcb')"></button>
            <button class="quick-color" style="background:#2ae500" onclick="onCustomColorChange('#2ae500')"></button>
            <button class="quick-color" style="background:#ff2dd1" onclick="onCustomColorChange('#ff2dd1')"></button>
            <button class="quick-color" style="background:#9d4dff" onclick="onCustomColorChange('#9d4dff')"></button>
            <button class="quick-color" style="background:#ffffff" onclick="onCustomColorChange('#ffffff')"></button>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <h3>Startup</h3>
      <div class="settings-list">
        <div class="row">
          <div class="left">
            <div class="ico">⚡</div>
            <div>
              <div class="title">Auto-connect on start</div>
              <div class="sub">Resume last active profile</div>
            </div>
          </div>
          <div class="toggle on" id="autoConnectToggle" onclick="toggleAutoConnect()"></div>
        </div>
        <div class="row">
          <div class="left">
            <div class="ico">🚀</div>
            <div>
              <div class="title">Launch with Windows</div>
              <div class="sub">Start minimized to tray on boot</div>
            </div>
          </div>
          <div class="toggle" id="autoStartToggle" onclick="toggleAutoStart()"></div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <h3>Tunnel Mode</h3>
      <div class="settings-list">
        <div class="row" onclick="setTunnelMode('mixed')" style="cursor:pointer">
          <div class="left">
            <div class="ico">🌐</div>
            <div>
              <div class="title">System Proxy (recommended)</div>
              <div class="sub">Local SOCKS/HTTP proxy. No admin needed.</div>
            </div>
          </div>
          <div class="radio-dot" id="modeMixedDot"></div>
        </div>
        <div class="row" onclick="setTunnelMode('tun')" style="cursor:pointer">
          <div class="left">
            <div class="ico">🔌</div>
            <div>
              <div class="title">TUN Interface</div>
              <div class="sub">Captures ALL traffic (games too). Requires admin.</div>
            </div>
          </div>
          <div class="radio-dot" id="modeTunDot"></div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <h3>Core Engine</h3>
      <div class="settings-list">
        <div class="row">
          <div class="left">
            <div class="ico">⚠</div>
            <div>
              <div class="title">Kill Switch</div>
              <div class="sub">Terminate all on core failure</div>
            </div>
          </div>
          <div class="toggle on" id="killSwitchToggle" onclick="toggleKillSwitch()"></div>
        </div>
        <div class="row">
          <div class="left">
            <div class="ico">📁</div>
            <div>
              <div class="title">Profiles Directory</div>
              <div class="sub">config/profiles/</div>
            </div>
          </div>
        </div>
        <div class="row">
          <div class="left">
            <div class="ico">📋</div>
            <div>
              <div class="title">Application Logs</div>
              <div class="sub">logs/notevil.log</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <h3>Network Logic</h3>
      <div class="card routing-card">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
          <span style="font-size:20px">⇄</span>
          <div style="font-size:14px">Routing Mode</div>
        </div>
        <div class="muted-sm" style="margin:4px 0 12px 30px">Reconnect to apply &middot; Global=all via VPN &middot; Rule=smart &middot; Direct=no VPN</div>
        <div class="routing-pill-group">
          <button class="routing-pill" id="rbGlobal" onclick="setRouting('Global')">Global</button>
          <button class="routing-pill active" id="rbRule" onclick="setRouting('Rule')">Rule</button>
          <button class="routing-pill" id="rbDirect" onclick="setRouting('Direct')">Direct</button>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <h3>Backup &amp; Transfer</h3>
      <div class="settings-list">
        <div class="row clickable" onclick="exportProfiles()">
          <div class="left">
            <div class="ico">📤</div>
            <div>
              <div class="title">Export All Profiles</div>
              <div class="sub">Save all server configs to ZIP archive</div>
            </div>
          </div>
          <div style="color:var(--txt4)">›</div>
        </div>
        <div class="row clickable" onclick="importProfiles()">
          <div class="left">
            <div class="ico">📥</div>
            <div>
              <div class="title">Import Profiles from ZIP</div>
              <div class="sub">Add profiles from a backup archive</div>
            </div>
          </div>
          <div style="color:var(--txt4)">›</div>
        </div>
      </div>
      <div class="muted-sm" style="padding:0 4px;margin-top:6px">Useful for backup or moving configs to another PC.</div>
    </div>

    <div class="settings-section">
      <h3>Shortcuts</h3>
      <div class="card" style="padding:14px;font-family:var(--mono);font-size:11px;color:var(--txt2);line-height:1.8">
        <div><b style="color:var(--accent)">Ctrl+Shift+V</b> &nbsp;Toggle VPN connection</div>
        <div><b style="color:var(--accent)">Ctrl+Shift+H</b> &nbsp;Show/hide window</div>
        <div><b style="color:var(--accent)">Ctrl+Shift+M</b> &nbsp;Switch to mini mode</div>
      </div>
    </div>

    <div class="settings-section">
      <h3>About</h3>
      <div class="card" style="padding:28px 20px;text-align:center">
        <div style="display:flex;flex-direction:column;align-items:center;gap:16px">

          <!-- Knot logo + N icon stacked -->
          <div style="position:relative;width:130px;height:130px;display:flex;align-items:center;justify-content:center">
            <!-- Knot glow bg -->
            <img src="data:image/png;base64,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"
              style="width:130px;height:130px;object-fit:contain;
                     filter:drop-shadow(0 0 24px var(--accent)) drop-shadow(0 0 50px var(--accent-dim)) brightness(1.3);
                     opacity:1;"
              draggable="false"/>
          </div>

          <!-- Brand name -->
          <div style="display:flex;flex-direction:column;align-items:center;gap:4px">
            <div style="font-family:var(--display);font-weight:700;color:var(--accent);font-size:26px;letter-spacing:-0.02em;line-height:1">not</div>
            <div style="font-family:var(--mono);font-size:10px;color:var(--txt4);letter-spacing:0.1em;margin-top:2px">v6.3 &nbsp;·&nbsp; sing-box core &nbsp;·&nbsp; AES-256-GCM</div>
          </div>

          <!-- GitHub link -->
          <a href="#"
            onclick="if(typeof bridge!='undefined'&&bridge){bridge.open_browser('https://github.com/notevil076');}return false;"
            style="display:inline-flex;align-items:center;gap:8px;
                   padding:9px 18px;border-radius:20px;
                   border:1px solid var(--accent-dim);
                   background:var(--accent-soft);
                   color:var(--accent);
                   font-family:var(--mono);font-size:11px;font-weight:500;
                   letter-spacing:0.06em;text-decoration:none;
                   transition:all .2s;cursor:pointer;"
            onmouseover="this.style.background='var(--accent-dim)';this.style.borderColor='var(--accent)'"
            onmouseout="this.style.background='var(--accent-soft)';this.style.borderColor='var(--accent-dim)'">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
            </svg>
            github.com/notevil076
          </a>

        </div>
      </div>
    </div>
    <div style="height:16px"></div>
  </div>

</main>


</div><!-- /.app-scroll -->

<nav class="bottom">
  <button class="active" data-tab="home" onclick="switchTab('home',this)"><div class="ico">⊞</div><div class="lbl">Home</div></button>
  <button data-tab="servers" onclick="switchTab('servers',this)"><div class="ico">≡</div><div class="lbl">Servers</div></button>
  <button data-tab="stats" onclick="switchTab('stats',this)"><div class="ico">⌶</div><div class="lbl">Stats</div></button>
  <button data-tab="settings" onclick="switchTab('settings',this)"><div class="ico">⚙</div><div class="lbl">Settings</div></button>
</nav>

<!-- MODAL -->
<div id="addModal" class="modal-bg">
  <div class="modal">
    <div class="modal-hd">
      <span style="font-size:20px;color:var(--accent)">+</span>
      <div class="title" id="modalTitle">Add Server</div>
      <button class="close-btn" onclick="closeAddModal()">×</button>
    </div>

    <!-- Mode tabs (add only) -->
    <div id="modalModeTabs" class="mode-tabs">
      <button class="mode-tab active" data-mode="single" onclick="setModalMode('single')">Single Key</button>
      <button class="mode-tab" data-mode="bulk" onclick="setModalMode('bulk')">Bulk Import</button>
    </div>

    <!-- Single mode fields -->
    <div id="singleFields">
      <div class="modal-field">
        <label class="field-label">SERVER NAME</label>
        <input id="modalName" class="input" placeholder="e.g. finland-01" />
      </div>
      <div class="modal-field">
        <label class="field-label">CONNECTION KEY</label>
        <textarea id="modalKey" class="input" rows="4" oninput="onKeyChange()" placeholder="hysteria2://... or vless://..."></textarea>
        <div class="muted-sm">Supports: hysteria2://, vless:// (including Reality)</div>
      </div>
      <div id="modalPreview" class="preview-box" style="display:none"></div>
    </div>

    <!-- Bulk mode fields -->
    <div id="bulkFields" style="display:none">
      <div class="modal-field">
        <label class="field-label">PASTE MULTIPLE KEYS (one per line)</label>
        <textarea id="modalBulkKeys" class="input" rows="10" placeholder="hysteria2://...&#10;vless://...&#10;vless://..." style="font-size:10px"></textarea>
        <div class="muted-sm">Names auto-generated from server addresses</div>
      </div>
    </div>

    <div id="modalError" class="modal-error" style="display:none"></div>

    <div class="modal-actions">
      <button class="btn-ghost" style="justify-content:center" onclick="closeAddModal()">CANCEL</button>
      <button class="btn-primary" id="modalSaveBtn" onclick="submitModal()">SAVE</button>
    </div>
  </div>
</div>

<!-- EDIT CONFIG MODAL -->
<div id="editModal" class="modal-bg">
  <div class="modal" style="max-width:520px">
    <div class="modal-hd">
      <span style="font-size:20px;color:var(--accent)">&#9881;</span>
      <div class="title" id="editTitle">Edit Config</div>
      <button class="close-btn" onclick="closeEditModal()">&times;</button>
    </div>
    <div class="modal-field">
      <label class="field-label">RAW JSON CONFIGURATION</label>
      <textarea id="editTextarea" class="input" rows="16" style="font-size:10px;line-height:1.5"></textarea>
      <div class="muted-sm">Edit with care. Invalid JSON will be rejected on save.</div>
    </div>
    <div id="editError" class="modal-error" style="display:none"></div>
    <div class="modal-actions">
      <button class="btn-ghost" style="justify-content:center" onclick="closeEditModal()">CANCEL</button>
      <button class="btn-primary" onclick="saveEditedConfig()">SAVE</button>
    </div>
  </div>
</div>

<!-- CONFIRM MODAL -->
<div id="confirmModal" class="modal-bg">
  <div class="modal" style="max-width:340px">
    <div class="modal-hd">
      <span style="font-size:20px;color:var(--error)">&#9888;</span>
      <div class="title" id="confirmTitle">Confirm</div>
    </div>
    <div id="confirmBody" style="color:var(--txt2);font-size:13px;line-height:1.5;margin-bottom:18px"></div>
    <div class="modal-actions">
      <button class="btn-ghost" style="justify-content:center" onclick="closeConfirmModal()">CANCEL</button>
      <button class="btn-danger" onclick="runConfirm()">CONFIRM</button>
    </div>
  </div>
</div>

<!-- TAG MODAL -->
<div id="tagModal" class="modal-bg">
  <div class="modal" style="max-width:380px">
    <div class="modal-hd">
      <span style="font-size:20px;color:var(--accent)">#</span>
      <div class="title">Set Tag</div>
      <button class="close-btn" onclick="closeTagModal()">&times;</button>
    </div>
    <div class="modal-field">
      <label class="field-label">TAG / GROUP NAME</label>
      <input id="tagInput" class="input" placeholder="e.g. Germany, Work, Backup" maxlength="32"/>
      <div class="muted-sm">Leave empty to remove tag. Profiles with the same tag are grouped.</div>
    </div>
    <div class="modal-field">
      <label class="field-label">EXISTING TAGS</label>
      <div id="tagSuggestions" style="display:flex;flex-wrap:wrap;gap:6px;min-height:24px"></div>
    </div>
    <div class="modal-actions">
      <button class="btn-ghost" style="justify-content:center" onclick="closeTagModal()">CANCEL</button>
      <button class="btn-primary" onclick="saveTag()">SAVE</button>
    </div>
  </div>
</div>

</div><!-- /.app-frame -->

<script>
let bridge = null;
const LOG_LIMIT = 200;

const S = {
  status: 'disconnected', selectedProfile: '', profiles: [],
  sessionStart: null, sparkData: Array(20).fill(0),
  pingData: {}, autoConnect: true, killSwitch: true, autoStart: false,
  routing: 'Rule', theme: 'green', customAccent: '#39ff14',
  totalDown: 0, totalUp: 0, logLines: [],
  modalMode: 'add', modalSubMode: 'single', modalRenameTarget: '',
  editTarget: '', pendingConfirm: null,
  healthMs: null, healthOk: null,
  tags: {}, tagFilter: '__all__', tagTarget: '',
  tunnelMode: 'mixed',
};

new QWebChannel(qt.webChannelTransport, ch => { bridge = ch.objects.bridge; init(); });

function init() {
  bridge.load_settings(raw => {
    try {
      const s = JSON.parse(raw || '{}');
      if (typeof s.auto_connect === 'boolean') { S.autoConnect = s.auto_connect; document.getElementById('autoConnectToggle').classList.toggle('on', S.autoConnect); }
      if (s.kill_switch === false) { S.killSwitch = false; document.getElementById('killSwitchToggle').classList.remove('on'); }
      if (s.routing) { S.routing = s.routing; highlightRouting(s.routing); }
      if (s.custom_accent) { S.customAccent = s.custom_accent; }
      // Always apply custom theme (text color only mode)
      const accent = s.custom_accent || S.customAccent || '#39ff14';
      const root = document.documentElement;
      root.classList.add('theme-custom');
      applyCustomAccent(accent);
      S.theme = 'custom';
      if (document.getElementById('customColorInput')) document.getElementById('customColorInput').value = accent;
      if (document.getElementById('customHexInput')) document.getElementById('customHexInput').value = accent;
      S.tunnelMode = s.tunnel_mode || 'mixed';
      updateTunnelModeUI();
    } catch {}
  });

  bridge.get_autostart(enabled => {
    S.autoStart = enabled;
    document.getElementById('autoStartToggle').classList.toggle('on', enabled);
  });

  refreshProfiles(() => {
    if (S.autoConnect) {
      bridge.get_last_profile(last => {
        if (last && S.profiles.includes(last)) {
          document.getElementById('profileSelect').value = last;
          S.selectedProfile = last;
          connectVpn(last);
          addLog('> AUTO-CONNECT: ' + last);
        }
      });
    }
  });

  refreshHistory();
  refreshTags();
  attachNodeListHandlers();
  buildSparkline();
  setInterval(tickSession, 1000);
  setInterval(updateSparkline, 1500);
}

function refreshProfiles(cb) {
  if (!bridge) return;
  bridge.get_profiles(p => {
    S.profiles = p || [];
    renderProfileSelect();
    bridge.get_tags(raw => {
      try { S.tags = JSON.parse(raw || '{}'); } catch {}
      renderTagFilter();
      renderNodeList(S.profiles);
      attachNodeListHandlers();
      if (cb) cb();
    });
  });
}
function renderProfileSelect() {
  const sel = document.getElementById('profileSelect');
  const cur = sel.value;
  sel.innerHTML = '<option value="">— select profile —</option>';
  S.profiles.forEach(p => {
    const o = document.createElement('option');
    o.value = p; o.textContent = p.replace('.json', '');
    sel.appendChild(o);
  });
  if (cur && S.profiles.includes(cur)) sel.value = cur;
}
function escHTML(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function renderNodeList(profiles, filter = '') {
  const list = document.getElementById('nodeList');
  let f = profiles.filter(p => p.toLowerCase().includes((filter || '').toLowerCase()));

  // Apply active tag filter
  if (S.tagFilter && S.tagFilter !== '__all__') {
    if (S.tagFilter === '__untagged__') {
      f = f.filter(p => !S.tags[p]);
    } else {
      f = f.filter(p => S.tags[p] === S.tagFilter);
    }
  }

  if (!f.length) { list.innerHTML = '<div class="empty">NO PROFILES FOUND</div>'; return; }

  // Group by tag (only if no filter active — otherwise flat list)
  const showGroups = !S.tagFilter || S.tagFilter === '__all__';
  let html = '';

  if (showGroups) {
    const groups = {};
    f.forEach(p => {
      const tag = S.tags[p] || '__untagged__';
      if (!groups[tag]) groups[tag] = [];
      groups[tag].push(p);
    });
    const order = Object.keys(groups).sort((a, b) => {
      if (a === '__untagged__') return 1;
      if (b === '__untagged__') return -1;
      return a.localeCompare(b);
    });
    for (const tag of order) {
      const label = tag === '__untagged__' ? 'UNTAGGED' : tag.toUpperCase();
      html += `<div class="tag-group-header">${escHTML(label)} <span class="tg-count">${groups[tag].length}</span></div>`;
      html += groups[tag].map(p => renderNodeRow(p)).join('');
    }
  } else {
    html = f.map(p => renderNodeRow(p)).join('');
  }

  list.innerHTML = html;
}

function renderNodeRow(p) {
  const ms = S.pingData[p];
  let cls, txt, dotCls = '';
  if (ms === undefined) { cls = 'wait'; txt = 'PING'; }
  else if (ms < 0)      { cls = 'off';  txt = 'OFFLINE'; dotCls = 'dead'; }
  else if (ms < 80)     { cls = 'good'; txt = ms + ' ms'; dotCls = 'alive'; }
  else if (ms < 180)    { cls = 'mid';  txt = ms + ' ms'; dotCls = 'alive'; }
  else                  { cls = 'bad';  txt = ms + ' ms'; dotCls = 'alive'; }
  const active = S.selectedProfile === p;
  const display = p.replace('.json', '');
  const tag = S.tags[p] || '';
  const tagBadge = tag ? `<span class="tag-chip">${escHTML(tag)}</span>` : '';
  const ep = escHTML(p);
  return `<div class="node-row ${active ? 'active' : ''}" data-profile="${ep}" data-action="select">
    <div class="status-circle ${dotCls}"></div>
    <div class="name">
      <div class="title">${escHTML(display)} ${tagBadge}</div>
      <div class="sub">${escHTML(display.toUpperCase())} // PROFILE</div>
    </div>
    <span class="ping-badge ${cls}">${txt}</span>
    <button class="menu-btn" data-profile="${ep}" data-action="menu" title="More">⋯</button>
    <div class="select-mark"></div>
  </div>`;
}

function refreshTags() {
  if (!bridge) return;
  bridge.get_tags(raw => {
    try {
      S.tags = JSON.parse(raw || '{}');
      renderTagFilter();
      renderNodeList(S.profiles, document.getElementById('nodeSearch').value);
    } catch {}
  });
}

function renderTagFilter() {
  const bar = document.getElementById('tagFilterBar');
  if (!bar) return;
  const tagSet = new Set();
  Object.values(S.tags).forEach(t => { if (t) tagSet.add(t); });
  const sortedTags = Array.from(tagSet).sort();
  const cur = S.tagFilter || '__all__';

  let html = `<button class="tag-pill ${cur === '__all__' ? 'active' : ''}" onclick="setTagFilter('__all__')">All</button>`;
  for (const t of sortedTags) {
    html += `<button class="tag-pill ${cur === t ? 'active' : ''}" onclick="setTagFilter(${JSON.stringify(t)})">${escHTML(t)}</button>`;
  }
  if (Object.values(S.tags).length < S.profiles.length) {
    html += `<button class="tag-pill ${cur === '__untagged__' ? 'active' : ''}" onclick="setTagFilter('__untagged__')">Untagged</button>`;
  }
  bar.innerHTML = html;
}

function setTagFilter(name) {
  S.tagFilter = name;
  renderTagFilter();
  renderNodeList(S.profiles, document.getElementById('nodeSearch').value);
}

function openTagModal(profile) {
  S.tagTarget = profile;
  const current = S.tags[profile] || '';
  document.getElementById('tagInput').value = current;
  // populate suggestions
  bridge.get_unique_tags(raw => {
    try {
      const tags = JSON.parse(raw || '[]');
      const sug = document.getElementById('tagSuggestions');
      sug.innerHTML = tags.map(t =>
        `<button class="tag-pill" onclick="document.getElementById('tagInput').value=${JSON.stringify(t)}">${escHTML(t)}</button>`
      ).join('');
    } catch {}
  });
  document.getElementById('tagModal').classList.add('show');
}
function closeTagModal() { document.getElementById('tagModal').classList.remove('show'); }
function saveTag() {
  const tag = document.getElementById('tagInput').value.trim();
  bridge.set_profile_tag(S.tagTarget, tag, res => {
    if (res === 'OK') {
      addLog('> TAG ' + (tag ? ('SET: ' + tag) : 'REMOVED') + ' on ' + S.tagTarget);
      closeTagModal();
      refreshTags();
    } else addLog('> ' + res);
  });
}

function attachNodeListHandlers() {
  const list = document.getElementById('nodeList');
  if (!list || list.dataset.bound === '1') return;
  list.dataset.bound = '1';
  list.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const profile = btn.dataset.profile;
    if (!profile) return;
    if (action === 'select') selectProfile(profile);
    else if (action === 'menu') { e.stopPropagation(); openContextMenu(btn, profile); }
  });
}

// ── Context menu (3-dots) ──
function openContextMenu(triggerBtn, profile) {
  closeContextMenu();
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.id = 'ctxMenu';
  menu.innerHTML = `
    <div class="item" data-act="rename"><span class="ic">✎</span> Rename profile</div>
    <div class="item" data-act="tag"><span class="ic">#</span> Set tag / group</div>
    <div class="item" data-act="copy"><span class="ic">⧉</span> Copy config to clipboard</div>
    <div class="item" data-act="edit"><span class="ic">⚙</span> View / Edit config</div>
    <div class="divider"></div>
    <div class="item danger" data-act="delete"><span class="ic">✕</span> Delete profile</div>
  `;
  document.body.appendChild(menu);
  const r = triggerBtn.getBoundingClientRect();
  let left = r.right - 200;
  if (left < 8) left = 8;
  let top = r.bottom + 4;
  if (top + 220 > window.innerHeight) top = r.top - 220;
  menu.style.left = left + 'px';
  menu.style.top = top + 'px';

  menu.addEventListener('click', (e) => {
    const it = e.target.closest('.item');
    if (!it) return;
    const act = it.dataset.act;
    closeContextMenu();
    if (act === 'rename')      openRenameModal(profile);
    else if (act === 'tag')    openTagModal(profile);
    else if (act === 'copy')   copyProfileConfig(profile);
    else if (act === 'edit')   openEditModal(profile);
    else if (act === 'delete') confirmDeleteProfile(profile);
  });

  setTimeout(() => document.addEventListener('click', closeContextMenuOnce, true), 0);
}
function closeContextMenuOnce(e) {
  if (e.target.closest('.ctx-menu')) return;
  closeContextMenu();
}
function closeContextMenu() {
  const m = document.getElementById('ctxMenu');
  if (m) m.remove();
  document.removeEventListener('click', closeContextMenuOnce, true);
}

function confirmDeleteProfile(p) {
  if (S.status === 'connected' && S.selectedProfile === p) {
    addLog('> CANNOT DELETE: profile is currently in use. Disconnect first.');
    return;
  }
  openConfirmModal(
    'Delete profile?',
    '"' + p.replace('.json','') + '" will be permanently removed.',
    () => deleteProfile(p)
  );
}

function copyProfileConfig(p) {
  if (!bridge) return;
  bridge.get_profile_text(p, txt => {
    if (txt && !txt.startsWith('ERROR')) {
      navigator.clipboard.writeText(txt).then(() => {
        addLog('> COPIED TO CLIPBOARD: ' + p);
      }).catch(() => addLog('> ERROR: clipboard unavailable'));
    } else {
      addLog('> ' + (txt || 'ERROR: cannot read profile'));
    }
  });
}

function openEditModal(p) {
  if (!bridge) return;
  bridge.get_profile_text(p, txt => {
    if (!txt || txt.startsWith('ERROR')) { addLog('> ' + (txt || 'ERROR')); return; }
    S.editTarget = p;
    document.getElementById('editTitle').textContent = 'Edit: ' + p.replace('.json','');
    document.getElementById('editTextarea').value = txt;
    document.getElementById('editError').style.display = 'none';
    document.getElementById('editModal').classList.add('show');
  });
}
function closeEditModal() {
  document.getElementById('editModal').classList.remove('show');
}
function saveEditedConfig() {
  const txt = document.getElementById('editTextarea').value;
  const err = document.getElementById('editError');
  err.style.display = 'none';
  try { JSON.parse(txt); }
  catch (e) { err.textContent = 'Invalid JSON: ' + e.message; err.style.display = ''; return; }
  bridge.set_profile_text(S.editTarget, txt, res => {
    if (res === 'OK') {
      addLog('> SAVED: ' + S.editTarget);
      closeEditModal();
    } else {
      err.textContent = res; err.style.display = '';
    }
  });
}

function openConfirmModal(title, body, onYes) {
  document.getElementById('confirmTitle').textContent = title;
  document.getElementById('confirmBody').textContent = body;
  S.pendingConfirm = onYes;
  document.getElementById('confirmModal').classList.add('show');
}
function closeConfirmModal() {
  S.pendingConfirm = null;
  document.getElementById('confirmModal').classList.remove('show');
}
function runConfirm() {
  if (S.pendingConfirm) S.pendingConfirm();
  closeConfirmModal();
}
function filterNodes(v) { renderNodeList(S.profiles, v); }
function selectProfile(n) {
  S.selectedProfile = n;
  document.getElementById('profileSelect').value = n;
  renderNodeList(S.profiles, document.getElementById('nodeSearch').value);
  addLog('> NODE SELECTED: ' + n);
}

function pingAll() {
  S.pingData = {};
  renderNodeList(S.profiles, document.getElementById('nodeSearch').value);
  const btn = document.getElementById('pingAllBtn');
  btn.disabled = true; btn.style.opacity = '.5';
  if (bridge) bridge.ping_all();
  setTimeout(() => { btn.disabled = false; btn.style.opacity = '1'; }, 9000);
}
function pingResult(name, ms) {
  S.pingData[name] = ms;
  renderNodeList(S.profiles, document.getElementById('nodeSearch').value);
  if (name === S.selectedProfile && ms >= 0)
    document.getElementById('latencyVal').textContent = ms + ' ms';
}

// ── Modal ──
function openAddModal() {
  S.modalMode = 'add';
  S.modalSubMode = 'single';
  document.getElementById('modalTitle').textContent = 'Add Server';
  document.getElementById('modalModeTabs').style.display = '';
  document.getElementById('singleFields').style.display = '';
  document.getElementById('bulkFields').style.display = 'none';
  document.querySelectorAll('.mode-tab').forEach(t => t.classList.toggle('active', t.dataset.mode === 'single'));
  document.getElementById('modalName').value = '';
  document.getElementById('modalKey').value = '';
  document.getElementById('modalBulkKeys').value = '';
  document.getElementById('modalPreview').style.display = 'none';
  document.getElementById('modalSaveBtn').textContent = 'SAVE';
  document.getElementById('modalError').style.display = 'none';
  document.getElementById('addModal').classList.add('show');
}
function openRenameModal(profileName) {
  S.modalMode = 'rename';
  S.modalRenameTarget = profileName;
  document.getElementById('modalTitle').textContent = 'Rename Profile';
  document.getElementById('modalModeTabs').style.display = 'none';
  document.getElementById('singleFields').style.display = '';
  document.getElementById('bulkFields').style.display = 'none';
  document.getElementById('modalName').value = profileName.replace('.json', '');
  document.getElementById('modalKey').parentElement.style.display = 'none';
  document.getElementById('modalPreview').style.display = 'none';
  document.getElementById('modalSaveBtn').textContent = 'RENAME';
  document.getElementById('modalError').style.display = 'none';
  document.getElementById('addModal').classList.add('show');
}
function closeAddModal() {
  document.getElementById('addModal').classList.remove('show');
  // Restore key field visibility for next add
  document.getElementById('modalKey').parentElement.style.display = '';
}
function setModalMode(m) {
  S.modalSubMode = m;
  document.querySelectorAll('.mode-tab').forEach(t => t.classList.toggle('active', t.dataset.mode === m));
  document.getElementById('singleFields').style.display = m === 'single' ? '' : 'none';
  document.getElementById('bulkFields').style.display = m === 'bulk' ? '' : 'none';
}

let previewTimer = null;
function onKeyChange() {
  if (previewTimer) clearTimeout(previewTimer);
  previewTimer = setTimeout(() => {
    const key = document.getElementById('modalKey').value.trim();
    const box = document.getElementById('modalPreview');
    if (!key) { box.style.display = 'none'; return; }
    bridge.preview_key(key, res => {
      try {
        const r = JSON.parse(res);
        if (r.ok) {
          box.className = 'preview-box ok';
          let html = '';
          for (const [k, v] of Object.entries(r.summary)) {
            html += `<div class="preview-row"><span class="pk">${k}</span><span class="pv">${v}</span></div>`;
          }
          box.innerHTML = html;
          box.style.display = '';
        } else {
          box.className = 'preview-box error';
          box.innerHTML = '<div style="color:var(--error)">⚠ ' + r.error + '</div>';
          box.style.display = '';
        }
      } catch {}
    });
  }, 400);
}

function submitModal() {
  const err = document.getElementById('modalError');
  err.style.display = 'none';

  if (S.modalMode === 'rename') {
    const name = document.getElementById('modalName').value.trim();
    if (!name) { err.textContent = 'Name cannot be empty.'; err.style.display = ''; return; }
    bridge.rename_profile(S.modalRenameTarget, name, res => {
      if (res.startsWith('OK:')) {
        const newName = res.slice(3);
        addLog('> RENAMED: ' + S.modalRenameTarget + ' → ' + newName);
        if (S.selectedProfile === S.modalRenameTarget) S.selectedProfile = newName;
        closeAddModal();
        refreshProfiles();
      } else { err.textContent = res; err.style.display = ''; }
    });
    return;
  }

  if (S.modalSubMode === 'bulk') {
    const text = document.getElementById('modalBulkKeys').value.trim();
    if (!text) { err.textContent = 'Paste at least one key.'; err.style.display = ''; return; }
    bridge.add_bulk_keys(text, S.routing, res => {
      try {
        const r = JSON.parse(res);
        addLog(`> BULK IMPORT: ${r.added.length} added, ${r.errors.length} errors`);
        if (r.errors.length) {
          r.errors.slice(0,5).forEach(e => addLog('> ' + e));
        }
        closeAddModal();
        refreshProfiles();
      } catch (e) {
        err.textContent = 'Import failed.';
        err.style.display = '';
      }
    });
  } else {
    const key = document.getElementById('modalKey').value.trim();
    const name = document.getElementById('modalName').value.trim();
    if (!key) { err.textContent = 'Paste a connection key first.'; err.style.display = ''; return; }
    bridge.add_server_key(key, name || 'server', S.routing, res => {
      if (res.startsWith('OK:')) {
        closeAddModal();
        addLog('> PROFILE SAVED: ' + res.slice(3));
        refreshProfiles();
      } else { err.textContent = res; err.style.display = ''; }
    });
  }
}

function deleteProfile(n) {
  if (!bridge) return;
  bridge.delete_profile(n, r => {
    if (r === 'OK') {
      addLog('> DELETED: ' + n);
      if (S.selectedProfile === n) S.selectedProfile = '';
      refreshProfiles();
    }
  });
}

// ── Connection ──
function handleConnect() {
  const p = document.getElementById('profileSelect').value;
  if (S.status === 'connected' || S.status === 'connecting' || S.status === 'unhealthy') {
    disconnectVpn();
  } else {
    if (!p) { addLog('> ERROR: Select a profile first'); return; }
    connectVpn(p);
  }
}
function connectVpn(p) {
  S.selectedProfile = p; S.totalDown = 0; S.totalUp = 0;
  S.healthOk = null; S.healthMs = null;
  document.getElementById('healthStatus').textContent = '—';
  setStatus('connecting');
  if (bridge) bridge.start_connection(p, S.routing);
}
function disconnectVpn() {
  if (bridge) bridge.stop_connection();
  setStatus('disconnected');
}

// Toggle VPN from hotkey/tray
function toggleVpn() {
  handleConnect();
}

function goMini() {
  if (bridge) bridge.show_mini();
}

// ── Custom titlebar ──
function onTitleDrag(e) {
  // Ignore clicks on buttons/links — only drag from bare areas
  if (e.target.closest('button')) return;
  if (e.button !== 0) return;
  if (bridge) bridge.win_start_drag();
}
function winMinimize() { if (bridge) bridge.win_minimize(); }
function winClose() { if (bridge) bridge.win_close(); }

function setStatus(s) {
  S.status = s;
  const dot = document.getElementById('statusDot');
  const lbl = document.getElementById('statusLabel');
  const bdot = document.getElementById('bigStatusDot');
  const btxt = document.getElementById('bigStatusText');
  const btn = document.getElementById('connectBtn');
  const albl = document.getElementById('activeProfileLabel');
  const rbadge = document.getElementById('routingBadge');
  const frame = document.getElementById('appFrame');

  if (dot) dot.className = 'status-dot';
  bdot.className = 'big-status-dot'; btxt.className = 'status-text';

  // Adaptive glow border: bright when connected/unhealthy, gray when offline
  if (frame) frame.classList.toggle('vpn-on', s === 'connected' || s === 'unhealthy');

  if (s === 'connected' || s === 'unhealthy') {
    const cls = s === 'unhealthy' ? 'unhealthy' : 'online';
    if (dot) dot.classList.add(cls); bdot.classList.add(cls); btxt.classList.add(cls);
    if (lbl) lbl.textContent = s === 'unhealthy' ? 'UNHEALTHY' : 'ONLINE';
    btxt.textContent = s === 'unhealthy' ? 'UNHEALTHY' : 'CONNECTED';
    btn.className = 'btn-danger'; btn.textContent = 'TERMINATE UPLINK';
    albl.textContent = S.selectedProfile.replace('.json', '') || '—';
    rbadge.textContent = '// ' + S.routing.toUpperCase();
    if (s === 'connected' && !S.sessionStart) S.sessionStart = Date.now();
  } else if (s === 'connecting') {
    if (dot) dot.classList.add('connecting'); bdot.classList.add('connecting'); btxt.classList.add('connecting');
    if (lbl) lbl.textContent = 'CONNECTING...';
    btxt.textContent = 'INITIALIZING...';
    btn.className = 'btn-primary disabled'; btn.textContent = 'CONNECTING...';
  } else {
    if (lbl) lbl.textContent = 'OFFLINE'; btxt.textContent = 'DISCONNECTED';
    btn.className = 'btn-primary'; btn.textContent = 'INITIALIZE UPLINK';
    albl.textContent = '—'; rbadge.textContent = '';
    S.sessionStart = null;
    document.getElementById('homeUpRate').textContent = '0 B/s';
    document.getElementById('homeDownRate').textContent = '0 B/s';
    document.getElementById('statDownRate').textContent = '0 B/s';
    document.getElementById('statUpRate').textContent = '0 B/s';
    document.getElementById('healthStatus').textContent = '—';
    S.chartUp = new Array(CHART_POINTS).fill(0);
    S.chartDown = new Array(CHART_POINTS).fill(0);
    refreshHistory();
  }
  btn.onclick = handleConnect;
}

function updateStats(up, down) {
  S.totalUp += up; S.totalDown += down;
  const fu = fmtRate(up), fd = fmtRate(down);
  document.getElementById('homeUpRate').textContent = fu;
  document.getElementById('homeDownRate').textContent = fd;
  document.getElementById('statUp').textContent = fmtBytes(S.totalUp);
  document.getElementById('statDown').textContent = fmtBytes(S.totalDown);
  document.getElementById('statUpRate').textContent = fu;
  document.getElementById('statDownRate').textContent = fd;
  S.sparkData.push(down); S.sparkData.shift();
  pushChartSample(up, down);
}
function fmtRate(b) {
  if (b < 1024) return b + ' B/s';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB/s';
  return (b/1048576).toFixed(2) + ' MB/s';
}
function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b/1048576).toFixed(2) + ' MB';
  return (b/1073741824).toFixed(3) + ' GB';
}

// Health check callbacks
function healthOk(ms) {
  S.healthOk = true; S.healthMs = ms;
  document.getElementById('healthStatus').textContent = ms + ' ms';
  document.getElementById('healthStatus').style.color = 'var(--accent)';
  if (S.status === 'unhealthy') setStatus('connected');
}
function healthFail(failCount) {
  S.healthOk = false;
  document.getElementById('healthStatus').textContent = 'FAIL ×' + failCount;
  document.getElementById('healthStatus').style.color = 'var(--warn)';
  if (failCount >= 3 && S.status === 'connected') setStatus('unhealthy');
}

function addLog(m) {
  S.logLines.push(m);
  if (S.logLines.length > LOG_LIMIT) S.logLines = S.logLines.slice(-LOG_LIMIT);
  const el = document.getElementById('logOutput');
  el.textContent = S.logLines.join('\n');
  el.scrollTop = el.scrollHeight;
}
function clearLog() { S.logLines = []; document.getElementById('logOutput').textContent = ''; }

function tickSession() {
  const el = document.getElementById('sessionTime');
  if (!S.sessionStart) { el.textContent = '00:00:00'; return; }
  const e = Date.now() - S.sessionStart;
  el.textContent = [Math.floor(e/3600000), Math.floor(e%3600000/60000), Math.floor(e%60000/1000)]
    .map(n => String(n).padStart(2,'0')).join(':');
}

// ── Throughput chart (60s history, 2 lines) ──
const CHART_POINTS = 60;
S.chartDown = new Array(CHART_POINTS).fill(0);
S.chartUp   = new Array(CHART_POINTS).fill(0);

function pushChartSample(up, down) {
  S.chartUp.push(up); S.chartUp.shift();
  S.chartDown.push(down); S.chartDown.shift();
}

function buildSparkline() { drawChart(); }

function drawChart() {
  const cnv = document.getElementById('chartCanvas');
  if (!cnv) return;
  // resolution fix
  const dpr = window.devicePixelRatio || 1;
  const rect = cnv.getBoundingClientRect();
  if (cnv.width !== Math.round(rect.width * dpr)) {
    cnv.width  = Math.round(rect.width * dpr);
    cnv.height = Math.round(rect.height * dpr);
  }
  const ctx = cnv.getContext('2d');
  const W = cnv.width, H = cnv.height;
  ctx.clearRect(0, 0, W, H);

  const styles = getComputedStyle(document.documentElement);
  const accent = styles.getPropertyValue('--accent').trim() || '#2ae500';
  const accentSoft = styles.getPropertyValue('--accent-soft').trim() || 'rgba(42,229,0,.15)';
  const border = styles.getPropertyValue('--border2').trim() || 'rgba(60,75,53,.25)';

  // Grid
  ctx.strokeStyle = border;
  ctx.lineWidth = 1 * dpr;
  for (let i = 1; i < 4; i++) {
    const y = (H / 4) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(W, y);
    ctx.stroke();
  }

  const maxVal = Math.max(...S.chartDown, ...S.chartUp, 1024);  // at least 1KB scale
  const pad = 4 * dpr;
  const innerH = H - pad * 2;
  const stepX = W / (CHART_POINTS - 1);

  // Helper to plot one series
  function plot(arr, color, fill) {
    if (fill) {
      ctx.beginPath();
      ctx.moveTo(0, H);
      for (let i = 0; i < CHART_POINTS; i++) {
        const y = H - pad - (arr[i] / maxVal) * innerH;
        ctx.lineTo(i * stepX, y);
      }
      ctx.lineTo(W, H);
      ctx.closePath();
      ctx.fillStyle = fill;
      ctx.fill();
    }
    ctx.beginPath();
    for (let i = 0; i < CHART_POINTS; i++) {
      const y = H - pad - (arr[i] / maxVal) * innerH;
      if (i === 0) ctx.moveTo(0, y);
      else ctx.lineTo(i * stepX, y);
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.8 * dpr;
    ctx.lineJoin = 'round';
    ctx.stroke();
  }

  // Up first (under), then Down (on top)
  plot(S.chartUp, '#b7c8e1', 'rgba(183,200,225,.1)');
  plot(S.chartDown, accent, accentSoft);

  // Y-axis label
  ctx.fillStyle = 'rgba(186,204,176,0.35)';
  ctx.font = `${9 * dpr}px 'JetBrains Mono', monospace`;
  ctx.textAlign = 'left';
  ctx.fillText(fmtRate(maxVal).toUpperCase(), 4 * dpr, 11 * dpr);
}

function updateSparkline() {
  drawChart();
}

function switchTab(t, btn) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('nav.bottom button').forEach(b => b.classList.remove('active'));
  document.getElementById('screen-' + t).classList.add('active');
  btn.classList.add('active');
  if (t === 'servers') renderNodeList(S.profiles, '');
  if (t === 'stats') refreshHistory();
}

function toggleAutoConnect() { S.autoConnect = !S.autoConnect; document.getElementById('autoConnectToggle').classList.toggle('on', S.autoConnect); saveSettings(); }
function toggleKillSwitch() { S.killSwitch = !S.killSwitch; document.getElementById('killSwitchToggle').classList.toggle('on', S.killSwitch); saveSettings(); }
function toggleAutoStart() {
  const target = !S.autoStart;
  bridge.set_autostart(target, ok => {
    if (ok) {
      S.autoStart = target;
      document.getElementById('autoStartToggle').classList.toggle('on', target);
      addLog('> AUTOSTART: ' + (target ? 'ENABLED' : 'DISABLED'));
    } else {
      addLog('> AUTOSTART: FAILED TO TOGGLE');
    }
  });
}
function setRouting(m) {
  S.routing = m;
  highlightRouting(m);
  addLog('> ROUTING SET: ' + m + ' (applies on next connect)');
  saveSettings();
}
function highlightRouting(m) {
  document.querySelectorAll('.routing-pill').forEach(b => b.classList.remove('active'));
  const map = { Global: 'rbGlobal', Rule: 'rbRule', Direct: 'rbDirect' };
  const el = document.getElementById(map[m]);
  if (el) el.classList.add('active');
}

function hexToRgb(h) {
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(h);
  return m ? { r: parseInt(m[1],16), g: parseInt(m[2],16), b: parseInt(m[3],16) } : null;
}
function isValidHex(h) {
  return /^#?[a-f\d]{6}$/i.test(h);
}

function applyCustomAccent(hex) {
  const c = hexToRgb(hex);
  if (!c) return;
  const root = document.documentElement;
  root.classList.add('theme-custom');
  root.style.setProperty('--custom-accent', hex);
  root.style.setProperty('--custom-soft',  `rgba(${c.r},${c.g},${c.b},.15)`);
  root.style.setProperty('--custom-dim',   `rgba(${c.r},${c.g},${c.b},.5)`);
  // Tint all text/border colors with the accent so entire UI shifts together
  root.style.setProperty('--txt',  `color-mix(in srgb, ${hex} 22%, #e8ffe8)`);
  root.style.setProperty('--txt2', `color-mix(in srgb, ${hex} 40%, rgba(180,200,180,.85))`);
  root.style.setProperty('--txt3', `color-mix(in srgb, ${hex} 28%, rgba(150,170,150,.5))`);
  root.style.setProperty('--txt4', `color-mix(in srgb, ${hex} 18%, rgba(120,140,120,.3))`);
  root.style.setProperty('--border',  `color-mix(in srgb, ${hex} 14%, rgba(60,70,60,.5))`);
  root.style.setProperty('--border2', `color-mix(in srgb, ${hex} 9%,  rgba(60,70,60,.25))`);
}

function setTheme(name, save = true) {
  S.theme = 'custom';
  const root = document.documentElement;
  root.classList.remove('theme-magenta', 'theme-violet', 'theme-custom');
  root.classList.add('theme-custom');
  // If called with a preset name, pick its color
  const presetColors = { green: '#2ae500', neon: '#2ae500', magenta: '#ff2dd1', violet: '#9d4dff' };
  if (presetColors[name]) {
    S.customAccent = presetColors[name];
    document.getElementById('customColorInput').value = S.customAccent;
    document.getElementById('customHexInput').value = S.customAccent;
  }
  applyCustomAccent(S.customAccent || '#39ff14');
  if (save) { saveSettings(); addLog('> TEXT COLOR: ' + (S.customAccent || '#39ff14').toUpperCase()); }
}

function openCustomTheme() {
  if (!S.customAccent) S.customAccent = '#39ff14';
  document.getElementById('customColorInput').value = S.customAccent;
  document.getElementById('customHexInput').value = S.customAccent;
  setTheme('custom');
}

function onCustomColorChange(hex) {
  if (!isValidHex(hex)) return;
  if (!hex.startsWith('#')) hex = '#' + hex;
  S.customAccent = hex;
  document.getElementById('customColorInput').value = hex;
  document.getElementById('customHexInput').value = hex;
  applyCustomAccent(hex);
  saveSettings();
}

function onCustomHexInput(value) {
  const v = value.trim();
  if (!isValidHex(v)) return;
  const hex = v.startsWith('#') ? v : ('#' + v);
  S.customAccent = hex;
  document.getElementById('customColorInput').value = hex;
  applyCustomAccent(hex);
  saveSettings();
}

function saveSettings() {
  if (!bridge) return;
  bridge.save_settings(JSON.stringify({
    auto_connect: S.autoConnect, kill_switch: S.killSwitch,
    routing: S.routing, theme: S.theme,
    custom_accent: S.customAccent,
    tunnel_mode: S.tunnelMode
  }));
}

function setTunnelMode(mode) {
  if (mode !== 'mixed' && mode !== 'tun') return;
  S.tunnelMode = mode;
  updateTunnelModeUI();
  saveSettings();
  addLog('> TUNNEL MODE: ' + mode.toUpperCase());
  // Warn if changing while connected
  if (S.status === 'connected' || S.status === 'unhealthy') {
    addLog('> [!] Reconnect required for mode change to apply');
  }
}

function updateTunnelModeUI() {
  const mDot = document.getElementById('modeMixedDot');
  const tDot = document.getElementById('modeTunDot');
  if (mDot) mDot.classList.toggle('on', S.tunnelMode === 'mixed');
  if (tDot) tDot.classList.toggle('on', S.tunnelMode === 'tun');
}

// ── History ──
function refreshHistory() {
  if (!bridge) return;
  bridge.get_history(raw => {
    try {
      const h = JSON.parse(raw || '[]');
      const list = document.getElementById('historyList');
      if (!h.length) { list.innerHTML = '<div class="empty">NO HISTORY YET</div>'; return; }
      list.innerHTML = h.slice(0, 20).map(e => {
        const d = new Date(e.start * 1000);
        const date = d.toLocaleDateString() + ' ' + d.toLocaleTimeString().slice(0, 5);
        const dur = fmtDur(e.duration);
        return `<div class="hist-item">
          <div class="top">
            <div class="name">${(e.profile || '').replace('.json','')}</div>
            <div class="date">${date}</div>
          </div>
          <div class="meta">
            <span><b>${dur}</b> session</span>
            <span>↓ <b>${fmtBytes(e.down)}</b></span>
            <span>↑ <b>${fmtBytes(e.up)}</b></span>
            <span>${e.routing || '—'}</span>
          </div>
        </div>`;
      }).join('');
    } catch {}
  });
}
function clearHistory() {
  if (bridge) bridge.clear_history();
  refreshHistory();
}
function fmtDur(s) {
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s/60) + 'm ' + (s%60) + 's';
  return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';
}

// ── Export/Import ──
function exportProfiles() {
  if (bridge) bridge.export_profiles_dialog();
}
function importProfiles() {
  if (bridge) bridge.import_profiles_dialog();
}
function notifyExport(count) { addLog('> EXPORTED ' + count + ' profiles'); }
function notifyImport(added, skipped) {
  addLog(`> IMPORTED ${added} profiles (${skipped} skipped)`);
  refreshProfiles();
}

window.addEventListener('load', buildSparkline);

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    document.body.style.display = 'none';
    void document.body.offsetHeight;
    document.body.style.display = '';
  }
});
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
#  MINI MODE WINDOW  (compact 240×100 widget)
# ─────────────────────────────────────────────
MINI_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<script src="qrc:///qtwebchannel/qwebchannel.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&family=DM+Mono:wght@400;500&display=swap');
:root {
  --accent: #2ae500; --accent-soft: rgba(42,229,0,.18); --accent-dim: rgba(42,229,0,.5);
  --bg: #080808; --bg2: #111111; --bg3: #161616;
  --txt: #efffe3; --txt2: #baccb0; --txt3: rgba(186,204,176,.5); --txt4: rgba(186,204,176,.3);
  --border: rgba(60,75,53,.5); --warn: #f5c542; --error: #ff6b6b;
}
.theme-magenta { --accent: #ff2dd1; --accent-soft: rgba(255,45,209,.18); --accent-dim: rgba(255,45,209,.5);
  --bg: #080808; --bg2: #111111; --bg3: #161616;
  --border: rgba(110,30,90,.5); }
.theme-violet { --accent: #9d4dff; --accent-soft: rgba(157,77,255,.18); --accent-dim: rgba(157,77,255,.5);
  --bg: #080808; --bg2: #111111; --bg3: #161616;
  --border: rgba(70,50,130,.5); }
.theme-custom { --accent: var(--custom-accent, #2ae500); --accent-soft: var(--custom-soft); --accent-dim: var(--custom-dim); }

* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  background: transparent; color: var(--txt);
  font-family: 'DM Sans', 'Segoe UI', sans-serif;
  -webkit-user-select: none; user-select: none;
  overflow: hidden;
}

.frame {
  width: 100vw; height: 100vh;
  background: rgba(6, 6, 6, 0.32);
  backdrop-filter: blur(24px) saturate(1.5);
  -webkit-backdrop-filter: blur(24px) saturate(1.5);
  border: 1px solid rgba(255,255,255,.1);
  border-radius: 24px;
  display: flex;
  flex-direction: column;
  position: relative;
  overflow: hidden;
  cursor: grab;
  transition: border-color .4s ease;
}
.frame:active { cursor: grabbing; }
.frame.vpn-on {
  border-color: var(--accent);
  animation: miniFramePulse 3.5s ease-in-out infinite;
}
@keyframes miniFramePulse {
  0%, 100% { border-color: var(--accent-dim); }
  50% { border-color: var(--accent); }
}
.frame::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  animation: laser 3.5s ease-in-out infinite;
}
@keyframes laser { 0%,100%{opacity:.3} 50%{opacity:1} }

/* Drag bar */
.bar {
  height: 18px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 6px 0 9px;
  -webkit-app-region: drag;
}
.bar .brand {
  font-family: 'DM Mono', 'Cascadia Mono', 'Consolas', monospace;
  font-size: 8px; font-weight: 700;
  letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--accent);
  opacity: 0.65;
}
.bar .ctrls {
  display: flex; gap: 2px;
  -webkit-app-region: no-drag;
}
.bar .ctrls button {
  background: none; border: none; cursor: pointer;
  color: var(--txt3); padding: 0;
  width: 18px; height: 14px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 3px;
  transition: all .15s;
}
.bar .ctrls button:hover { background: rgba(255,255,255,0.08); color: var(--txt); }
.bar .ctrls button.close:hover { background: rgba(255,49,49,.2); color: #ff6b6b; }
.bar .ctrls svg { width: 8px; height: 8px; }

/* Body */
.body {
  flex: 1;
  padding: 4px 12px 6px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.status-col { flex: 1; min-width: 0; }
.status-line {
  display: flex; align-items: center; gap: 6px;
  margin-bottom: 2px;
}
.dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--txt4);
  flex-shrink: 0;
  transition: all .3s;
}
.dot.on { background: var(--accent); box-shadow: 0 0 6px var(--accent); animation: pulse 1.4s infinite; }
.dot.warn { background: var(--warn); animation: pulse 1s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
.st {
  font-family: 'DM Mono', 'Cascadia Mono', 'Consolas', monospace;
  font-size: 10px; font-weight: 700;
  letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--txt2);
}
.st.on { color: var(--accent); }
.st.warn { color: var(--warn); }
.pf {
  font-size: 11px; color: var(--txt);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  margin-left: 13px;
}
.pf-empty { color: var(--txt4); font-style: italic; }

/* Power button */
.power {
  flex-shrink: 0;
  width: 38px; height: 38px;
  border-radius: 50%;
  border: 1.5px solid var(--accent-dim);
  background: transparent;
  cursor: pointer;
  transition: all .25s;
  display: flex; align-items: center; justify-content: center;
  position: relative;
}
.power svg {
  width: 16px; height: 16px;
  stroke: var(--accent); fill: none;
  stroke-width: 2.2; stroke-linecap: round;
  transition: stroke .25s;
}
.power:hover {
  border-color: var(--accent);
  background: var(--accent-soft);
  box-shadow: 0 0 12px var(--accent-soft);
}
.power.on {
  background: var(--accent);
  border-color: var(--accent);
  box-shadow: 0 0 14px var(--accent-dim);
}
.power.on svg { stroke: var(--bg); }
.power.on::after {
  content: ''; position: absolute; inset: -4px;
  border-radius: 50%; border: 1px solid var(--accent-dim);
  animation: ring 2s ease-in-out infinite;
}
@keyframes ring {
  0%,100% { opacity: .2; transform: scale(1); }
  50% { opacity: .6; transform: scale(1.08); }
}

/* Footer rates */
.foot {
  display: flex; align-items: center; justify-content: space-between;
  padding: 4px 12px 6px;
  font-family: 'DM Mono', 'Cascadia Mono', 'Consolas', monospace;
  font-size: 9px;
  border-top: 1px solid var(--border);
  color: var(--txt3);
}
.foot .grp { display: flex; gap: 12px; }
.foot .r { display: flex; align-items: center; gap: 3px; }
.foot .r .arr { color: var(--txt4); font-size: 10px; }
.foot .r b { color: var(--accent); font-weight: 700; letter-spacing: 0.02em; }
.foot .r.up b { color: var(--txt2); }
.foot .dur { color: var(--txt2); font-weight: 700; letter-spacing: 0.08em; }
</style></head>
<body>
<div class="frame" id="frame" onmousedown="onMiniDrag(event)">
  <div class="bar">
    <span class="brand"></span>
    <div class="ctrls" onmousedown="event.stopPropagation()">
      <button id="expandBtn" title="Expand">
        <svg viewBox="0 0 12 12"><path d="M 2 4 L 2 2 L 4 2 M 8 2 L 10 2 L 10 4 M 10 8 L 10 10 L 8 10 M 4 10 L 2 10 L 2 8" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </button>
      <button class="close" id="closeBtn" title="Close">
        <svg viewBox="0 0 12 12"><path d="M 3 3 L 9 9 M 9 3 L 3 9" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round"/></svg>
      </button>
    </div>
  </div>

  <div class="body">
    <div class="status-col">
      <div class="status-line">
        <div class="dot" id="dot"></div>
        <span class="st" id="st">OFFLINE</span>
      </div>
      <div class="pf pf-empty" id="pf">no profile</div>
    </div>
    <button class="power" id="cbtn" title="Toggle VPN (Ctrl+Shift+V)" onmousedown="event.stopPropagation()">
      <svg viewBox="0 0 24 24">
        <path d="M 12 4 L 12 12"/>
        <path d="M 7.5 7 A 7 7 0 1 0 16.5 7"/>
      </svg>
    </button>
  </div>

  <div class="foot">
    <div class="grp">
      <span class="r"><span class="arr">↓</span><b id="dn">0 B/s</b></span>
      <span class="r up"><span class="arr">↑</span><b id="up">0 B/s</b></span>
    </div>
    <span class="dur" id="durBox">--:--</span>
  </div>
</div>

<script>
let bridge = null;
const M = { status: 'disconnected', profile: '', sessionStart: null, theme: 'green', customAccent: '#39ff14' };

new QWebChannel(qt.webChannelTransport, ch => { bridge = ch.objects.bridge; init(); });

function init() {
  bridge.load_settings(raw => {
    try {
      const s = JSON.parse(raw || '{}');
      if (s.theme) applyTheme(s.theme, s.custom_accent);
    } catch {}
  });
  syncStateFromMain();
  setInterval(syncStateFromMain, 1200);
  setInterval(tickDur, 1000);
  document.getElementById('cbtn').onclick = () => bridge.mini_toggle_vpn();
  document.getElementById('expandBtn').onclick = () => bridge.mini_expand();
  document.getElementById('closeBtn').onclick = () => bridge.mini_close();
}

// Drag from anywhere on the mini window — calls native Win32 drag via bridge
function onMiniDrag(e) {
  if (e.button !== 0) return;  // left mouse only
  if (!bridge) return;
  bridge.mini_start_drag();
}

function applyTheme(name, customAccent) {
  const root = document.documentElement;
  root.classList.remove('theme-magenta','theme-violet','theme-custom');
  if (name === 'magenta') root.classList.add('theme-magenta');
  else if (name === 'violet') root.classList.add('theme-violet');
  else if (name === 'custom' && customAccent) {
    root.classList.add('theme-custom');
    root.style.setProperty('--custom-accent', customAccent);
    const c = hexToRgb(customAccent);
    if (c) {
      root.style.setProperty('--custom-soft', `rgba(${c.r},${c.g},${c.b},.18)`);
      root.style.setProperty('--custom-dim',  `rgba(${c.r},${c.g},${c.b},.5)`);
    }
  }
}
function hexToRgb(h) {
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(h);
  return m ? { r: parseInt(m[1],16), g: parseInt(m[2],16), b: parseInt(m[3],16) } : null;
}

function syncStateFromMain() {
  bridge.mini_get_state(raw => {
    try {
      const s = JSON.parse(raw);
      M.status = s.status;
      M.profile = s.profile;
      M.sessionStart = s.session_start;
      // Apply theme dynamically (so changes in main window propagate)
      if (s.theme && s.theme !== M.theme) {
        M.theme = s.theme;
        applyTheme(s.theme, s.custom_accent);
      } else if (s.theme === 'custom' && s.custom_accent && s.custom_accent !== M.customAccent) {
        M.customAccent = s.custom_accent;
        applyTheme('custom', s.custom_accent);
      }
      renderState(s);
    } catch {}
  });
}

function renderState(s) {
  const dot = document.getElementById('dot');
  const st = document.getElementById('st');
  const pf = document.getElementById('pf');
  const btn = document.getElementById('cbtn');
  const frame = document.getElementById('frame');

  dot.className = 'dot';
  st.className = 'st';
  btn.classList.remove('on');

  // Adaptive glow: vpn-on when connected or unhealthy
  if (frame) frame.classList.toggle('vpn-on', s.status === 'connected' || s.status === 'unhealthy');

  if (s.status === 'connected') {
    dot.classList.add('on'); st.classList.add('on');
    st.textContent = 'CONNECTED';
    btn.classList.add('on');
  } else if (s.status === 'unhealthy') {
    dot.classList.add('warn'); st.classList.add('warn');
    st.textContent = 'UNHEALTHY';
    btn.classList.add('on');
  } else if (s.status === 'connecting') {
    dot.classList.add('warn'); st.classList.add('warn');
    st.textContent = 'CONNECTING';
  } else {
    st.textContent = 'OFFLINE';
  }

  const profDisplay = (s.profile || '').replace('.json', '');
  if (profDisplay) {
    pf.textContent = profDisplay;
    pf.classList.remove('pf-empty');
  } else {
    pf.textContent = 'no profile';
    pf.classList.add('pf-empty');
  }
  document.getElementById('dn').textContent = s.down_rate || '0 B/s';
  document.getElementById('up').textContent = s.up_rate || '0 B/s';
}

function tickDur() {
  const el = document.getElementById('durBox');
  if (!M.sessionStart) { el.textContent = '--:--'; return; }
  const e = Date.now()/1000 - M.sessionStart;
  const h = Math.floor(e/3600), m = Math.floor((e%3600)/60), s = Math.floor(e%60);
  el.textContent = (h ? h+':' : '') + String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
}
</script>
</body></html>"""


class MiniWindow(QMainWindow):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("not NETWORK · mini")
        self.setWindowIcon(main_window._icon)
        self.setFixedSize(260, 108)
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.FramelessWindowHint
        )
        # transparent background so rounded corners look clean
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

        self.view = QWebEngineView()
        self.view.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        self.view.settings().setAttribute(QWebEngineSettings.WebAttribute.ShowScrollBars, False)
        self.view.page().setBackgroundColor(Qt.GlobalColor.transparent)

        # reuse the same bridge for state sync
        self.bridge = main_window.bridge
        self.channel = QWebChannel()
        self.channel.registerObject("bridge", self.bridge)
        self.view.page().setWebChannel(self.channel)
        # register native drag callback for mini window
        self.bridge._mini_drag_cb = self._start_native_drag

        cw = QWidget()
        layout = QVBoxLayout(cw)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.view)
        self.setCentralWidget(cw)
        self.view.setHtml(MINI_HTML, QUrl("qrc:///"))

        # frameless window dragging (Qt-level — for direct mouse events outside webview)
        self._drag_pos = None

    def _start_native_drag(self):
        """Native Win32 drag — works from anywhere inside the mini window."""
        try:
            WM_NCLBUTTONDOWN = 0x00A1
            HTCAPTION = 2
            hwnd = int(self.winId())
            ctypes.windll.user32.ReleaseCapture()
            ctypes.windll.user32.SendMessageW(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0)
        except Exception as e:
            log.error(f"mini native_drag: {e}")

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_pos and event.buttons() & Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def closeEvent(self, event):
        # closing mini = back to main window
        event.ignore()
        self.hide()
        self.main_window._show_window()


# ─────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────
class NotEvilNetApp(QMainWindow):
    def __init__(self, start_minimized=False):
        super().__init__()
        self.setWindowTitle("not NETWORK")
        self._icon = QIcon(ICON_PATH) if os.path.exists(ICON_PATH) else QIcon()
        self.setWindowIcon(self._icon)
        self.setFixedSize(440, 850)
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.FramelessWindowHint
        )
        # Translucent background allows CSS border-radius to show through (iPhone-style rounded corners)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._start_minimized = start_minimized
        self.setAcceptDrops(True)
        self._mini_window = None
        self._drag_pos = None

        self.bridge = Bridge(self)
        # extend bridge with dialog methods (need QFileDialog from window)
        self.bridge.export_profiles_dialog = self._export_dialog
        self.bridge.import_profiles_dialog = self._import_dialog

        self.view = QWebEngineView()
        self.view.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        self.view.settings().setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, False)
        self.view.settings().setAttribute(QWebEngineSettings.WebAttribute.ShowScrollBars, False)
        # Transparent QWebEngineView so HTML can use border-radius / box-shadow
        self.view.page().setBackgroundColor(Qt.GlobalColor.transparent)
        self.view.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.view.setStyleSheet("background: transparent;")

        self.channel = QWebChannel()
        # Register bridge with all its methods
        self.channel.registerObject("bridge", self.bridge)
        self.view.page().setWebChannel(self.channel)
        self.bridge.set_web_page(self.view.page())
        self.bridge.show_notification.connect(self._show_notification)
        self.bridge._mini_show_cb = self._show_mini
        self.bridge._win_minimize_cb = self.showMinimized
        self.bridge._win_close_cb = self.hide
        self.bridge._win_drag_cb = self._start_native_drag

        w = QWidget()
        w.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.view)
        self.setCentralWidget(w)
        self.view.setHtml(APP_HTML, QUrl("qrc:///"))

        self._setup_tray()
        self._setup_shortcuts()

    def _setup_tray(self):
        self.tray = QSystemTrayIcon(self._icon, self)
        self.tray.setToolTip("not NETWORK")

        menu = QMenu()
        act_show = QAction("Show", self)
        act_show.triggered.connect(self._show_window)
        act_mini = QAction("Mini mode", self)
        act_mini.triggered.connect(self._show_mini)
        act_toggle = QAction("Toggle VPN", self)
        act_toggle.triggered.connect(lambda: self.bridge.js("toggleVpn();"))
        act_quit = QAction("Quit", self)
        act_quit.triggered.connect(self._quit_app)
        menu.addAction(act_show)
        menu.addAction(act_mini)
        menu.addAction(act_toggle)
        menu.addSeparator()
        menu.addAction(act_quit)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        self.tray.show()

    def _setup_shortcuts(self):
        sc_toggle = QShortcut(QKeySequence("Ctrl+Shift+V"), self)
        sc_toggle.setContext(Qt.ShortcutContext.ApplicationShortcut)
        sc_toggle.activated.connect(lambda: self.bridge.js("toggleVpn();"))

        sc_hide = QShortcut(QKeySequence("Ctrl+Shift+H"), self)
        sc_hide.setContext(Qt.ShortcutContext.ApplicationShortcut)
        sc_hide.activated.connect(self._toggle_window)

        sc_mini = QShortcut(QKeySequence("Ctrl+Shift+M"), self)
        sc_mini.setContext(Qt.ShortcutContext.ApplicationShortcut)
        sc_mini.activated.connect(self._show_mini)

    def _toggle_window(self):
        if self.isVisible() and not self.isMinimized():
            self.hide()
        else:
            self._show_window()

    def _tray_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.DoubleClick,
                      QSystemTrayIcon.ActivationReason.Trigger):
            self._show_window()

    def _show_window(self):
        self.showNormal()
        self.activateWindow()
        self.raise_()
        self.view.page().runJavaScript(
            "document.body.style.display='none';"
            "void document.body.offsetHeight;"
            "document.body.style.display='';"
        )
        # if mini was open — close it
        if self._mini_window is not None:
            self._mini_window.hide()

    def _show_mini(self):
        if self._mini_window is None:
            self._mini_window = MiniWindow(self)
            self.bridge._mini_expand_cb = self._show_window
            self.bridge._mini_close_cb = lambda: (self._mini_window.hide() if self._mini_window else None)
            # position mini in bottom-right corner
            screen = QApplication.primaryScreen().availableGeometry()
            x = screen.right() - 260
            y = screen.bottom() - 120
            self._mini_window.move(x, y)
        self.hide()
        self._mini_window.show()
        self._mini_window.raise_()
        self._mini_window.activateWindow()
        # ensure callback wired
        self.bridge._mini_show_cb = self._show_mini

    def _show_notification(self, title: str, body: str, level: str):
        icon = QSystemTrayIcon.MessageIcon.Information
        if level == "warning": icon = QSystemTrayIcon.MessageIcon.Warning
        elif level == "error": icon = QSystemTrayIcon.MessageIcon.Critical
        self.tray.showMessage(title, body, icon, 4000)

    def _export_dialog(self):
        default = os.path.join(os.path.expanduser("~"), "Desktop",
                               f"notevil-profiles-{datetime.now():%Y%m%d}.zip")
        path, _ = QFileDialog.getSaveFileName(self, "Export profiles", default,
                                              "ZIP archives (*.zip)")
        if not path: return
        if not path.endswith(".zip"): path += ".zip"
        result = self.bridge.export_profiles(path)
        if result.startswith("OK:"):
            count = result.split(":")[1]
            self.bridge.js(f"notifyExport({count});")
            self._show_notification("Export complete", f"Saved {count} profiles", "info")

    def _import_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import profiles", "",
                                              "ZIP archives (*.zip)")
        if not path: return
        result = self.bridge.import_profiles(path)
        try:
            r = json.loads(result)
            self.bridge.js(f"notifyImport({r['added']},{r['skipped']});")
            self._show_notification("Import complete",
                f"Added {r['added']}, skipped {r['skipped']}", "info")
        except Exception:
            self._show_notification("Import failed", str(result), "error")

    def _quit_app(self):
        self.bridge.stop_connection()
        # Extra safety: cleanup again in case stop_connection didn't fully clean
        try:
            cleanup_singbox_resources()
        except Exception:
            pass
        if self._mini_window is not None:
            self._mini_window.hide()
        self.tray.hide()
        log.info("App quit")
        QApplication.quit()

    def changeEvent(self, event):
        if event.type() == QEvent.Type.WindowStateChange:
            if self.isMinimized():
                event.accept()
                self.hide()
                return
        super().changeEvent(event)

    def closeEvent(self, event):
        event.ignore()
        self.hide()

    def _start_native_drag(self):
        """Use Windows WM_NCLBUTTONDOWN to drag the window — native smooth feel."""
        try:
            WM_NCLBUTTONDOWN = 0x00A1
            HTCAPTION = 2
            hwnd = int(self.winId())
            ctypes.windll.user32.ReleaseCapture()
            ctypes.windll.user32.SendMessageW(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0)
        except Exception as e:
            log.error(f"native_drag: {e}")

    # ── Drag & Drop ──
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                path = url.toLocalFile().lower()
                if path.endswith('.txt') or path.endswith('.zip') or path.endswith('.json'):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        added_txt = 0
        added_zip = 0
        added_json = 0
        errors = []
        for url in urls:
            path = url.toLocalFile()
            lp = path.lower()
            try:
                if lp.endswith('.zip'):
                    result = self.bridge.import_profiles(path)
                    try:
                        r = json.loads(result)
                        added_zip += r.get('added', 0)
                    except Exception:
                        errors.append(f"ZIP: {result}")
                elif lp.endswith('.txt'):
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        text = f.read()
                    result = self.bridge.add_bulk_keys(text, "Rule")
                    try:
                        r = json.loads(result)
                        added_txt += len(r.get('added', []))
                        errors.extend(r.get('errors', [])[:3])
                    except Exception:
                        errors.append(f"TXT: {result}")
                elif lp.endswith('.json'):
                    # treat as single profile config — copy in
                    import shutil
                    target = os.path.join(PROFILES_DIR, os.path.basename(path))
                    if not os.path.exists(target):
                        shutil.copy2(path, target)
                        added_json += 1
                    else:
                        errors.append(f"{os.path.basename(path)} already exists")
            except Exception as e:
                errors.append(f"{os.path.basename(path)}: {e}")

        # refresh UI
        self.bridge.js("refreshProfiles();")
        total = added_txt + added_zip + added_json
        parts = []
        if added_txt: parts.append(f"{added_txt} from TXT")
        if added_zip: parts.append(f"{added_zip} from ZIP")
        if added_json: parts.append(f"{added_json} JSON")
        msg = " · ".join(parts) if parts else "no new profiles"
        self._show_notification("Drag & Drop",
            f"Imported {total} profiles ({msg})",
            "info" if total > 0 else "warning")
        for err in errors[:3]:
            self.bridge.js(f"addLog({json.dumps('> DROP ERROR: ' + err)});")
        log.info(f"Drag&Drop: added={total}, errors={len(errors)}")


# ─────────────────────────────────────────────
#  ENTRY
# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        ensure_single_instance()

        start_minimized = "--minimized" in sys.argv

        if not is_admin():
            try:
                args = f'"{os.path.abspath(sys.argv[0])}"'
                if start_minimized: args += ' --minimized'
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, args, None, 1)
                sys.exit()
            except Exception:
                pass

        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        app.setQuitOnLastWindowClosed(False)
        window = NotEvilNetApp(start_minimized=start_minimized)
        if not start_minimized:
            window.show()

        # Defer cleanup so the window appears instantly.
        # User won't try to connect within first 800ms anyway — cleanup will be done by then.
        def _deferred_cleanup():
            try:
                cleanup_singbox_resources()
            except Exception as e:
                log.error(f"deferred cleanup: {e}")
        QTimer.singleShot(800, _deferred_cleanup)

        sys.exit(app.exec())
    except Exception as e:
        import traceback
        with open(os.path.join(get_base_path(), "crash.log"), "w", encoding="utf-8") as f:
            traceback.print_exc(file=f)
            f.write(f"\nError: {e}\n")
        log.error(f"Crash: {e}", exc_info=True)
        traceback.print_exc()
        input("Press Enter to exit...")
