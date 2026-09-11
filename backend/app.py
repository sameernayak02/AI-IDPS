import os
import asyncio
import json
import threading
import requests
import subprocess
import socket
import base64
import platform
import re
import ipaddress
import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from collections import defaultdict

# Framework & Security Imports
from fastapi import FastAPI, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from dotenv import load_dotenv

# Network & Project Logic Imports
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, ICMP, conf
from auth import Token, create_access_token, get_current_user, verify_admin_role, ACCESS_TOKEN_EXPIRE_MINUTES
from honeypot import start_honeypot_service, honeypot_trigger_logic

# --- Initialization ---
load_dotenv()
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="AI-Powered IDS API", description="API for Intrusion Detection System")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# --- Security: CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- MongoDB Setup (optional) ---
ENABLE_MONGODB = os.getenv("ENABLE_MONGODB", "false").lower() == "true"
db_collection = None
if ENABLE_MONGODB:
    try:
        import base64
        from pymongo import MongoClient
        uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        db_name = os.getenv("MONGODB_DB_NAME", "IDS")
        mongo_client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        mongo_client.server_info()  # test connection
        ids_db = mongo_client[db_name]
        db_collection = ids_db["traffic_logs"]
        admin_collection = ids_db["admin"]
        analyst_collection = ids_db["analyst"]
        headadmin_collection = ids_db["headadmin"]
        anomaly_ips_collection = ids_db["anomaly_ips"]
        blocked_ips_collection = ids_db["blocked_ips"]
        print(f"[MongoDB] Connected successfully to database: {db_name}")
    except Exception as e:
        print(f"[MongoDB] Connection failed (running without persistence): {e}")
        db_collection = None
        admin_collection = None
        analyst_collection = None
        headadmin_collection = None
        anomaly_ips_collection = None
        blocked_ips_collection = None
else:
    admin_collection = None
    analyst_collection = None
    headadmin_collection = None
    anomaly_ips_collection = None
    blocked_ips_collection = None

# --- Pydantic Data Models ---
class LogEntry(BaseModel):
    id: int
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol: str
    length: int
    prediction: str = Field(..., description="Normal or Anomaly")
    threat_level: float = Field(..., ge=0.0, le=1.0)

class Alert(BaseModel):
    message: str
    severity: str
    timestamp: str

class IPBlockRequest(BaseModel):
    ip: str

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: str = "Analyst"
    first_name: str = Field(..., min_length=1)
    middle_name: Optional[str] = None
    last_name: str = Field(..., min_length=1)
    email: str = Field(..., pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    mobile: str = Field(..., pattern=r"^\+?1?\d{9,15}$")
    dob: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    city: Optional[str] = None

    @validator('username')
    def username_valid(cls, v):
        import re
        if not re.match(r"^[a-zA-Z0-9@._-]+$", v):
            raise ValueError('Username can only contain letters, numbers, @, ., _, and -')
        return v

    @validator('mobile')
    def sanitize_mobile(cls, v):
        # Allow spaces, dashes, and parens but strip them for the final value
        import re
        sanitized = re.sub(r"[\s\-\(\)]", "", v)
        if not re.match(r"^\+?\d{9,15}$", sanitized):
            raise ValueError('Invalid mobile number format')
        return sanitized

# --- Pending Registration Persistence ---
PENDING_FILE = os.path.join(os.path.dirname(__file__), "pending_requests.json")

def load_pending():
    if not os.path.exists(PENDING_FILE): return {}
    try:
        with open(PENDING_FILE, "r") as f: return json.load(f)
    except: return {}

def save_pending(data):
    with open(PENDING_FILE, "w") as f: json.dump(data, f, indent=4)

# --- Head Admin Profile Persistence ---
PROFILE_FILE = os.path.join(os.path.dirname(__file__), "head_admin_profile.json")

def load_head_profile():
    if not os.path.exists(PROFILE_FILE):
        return {
            "fullname": "Alexander Vanguard",
            "uid": "HA-8829-X",
            "phone": "+1 (555) 948-2039",
            "email": "a.vanguard@ids.security",
            "dob": "March 14, 1985"
        }
    try:
        with open(PROFILE_FILE, "r") as f: return json.load(f)
    except: return {}

def save_head_profile(data):
    with open(PROFILE_FILE, "w") as f: json.dump(data, f, indent=4)

# --- Admin Profile Persistence ---
ADMIN_PROFILES_FILE = os.path.join(os.path.dirname(__file__), "admin_profiles.json")

def load_admin_profiles():
    if not os.path.exists(ADMIN_PROFILES_FILE): return {}
    try:
        with open(ADMIN_PROFILES_FILE, "r") as f: return json.load(f)
    except: return {}

def save_admin_profiles(data):
    with open(ADMIN_PROFILES_FILE, "w") as f: json.dump(data, f, indent=4)

# --- Analyst Profile Persistence ---
ANALYST_PROFILES_FILE = os.path.join(os.path.dirname(__file__), "analyst_profiles.json")

def load_analyst_profiles():
    if not os.path.exists(ANALYST_PROFILES_FILE): return {}
    try:
        with open(ANALYST_PROFILES_FILE, "r") as f: return json.load(f)
    except: return {}

def save_analyst_profiles(data):
    with open(ANALYST_PROFILES_FILE, "w") as f: json.dump(data, f, indent=4)
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

def load_users():
    defaults = {
        "headadmin": {"password": os.getenv("HEAD_ADMIN_PASSWORD", "headadmin"), "role": "HeadAdmin"},
        "admin": {"password": os.getenv("ADMIN_PASSWORD", "admin"), "role": "Admin"},
        "analyst": {"password": os.getenv("ANALYST_PASSWORD", "analyst"), "role": "Analyst"}
    }
    if not os.path.exists(USERS_FILE):
        return defaults
    
    try:
        with open(USERS_FILE, "r") as f:
            stored = json.load(f)
            # Merge defaults into stored so headadmin always exists
            for k, v in defaults.items():
                if k not in stored: stored[k] = v
            return stored
    except Exception:
        return defaults

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

# --- WebSocket Connection Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        # Automatically record security alerts to global history
        if message.get("type") == "alert" and message.get("data"):
            alerts_history.append(message["data"])
            if len(alerts_history) > 100:
                alerts_history.pop(0)

        payload = json.dumps(message)
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                dead.append(connection)
        for c in dead:
            self.disconnect(c)

manager = ConnectionManager()
BLACKLIST_IPS = set()
blocked_ips = set()
detections = []

# --- GeoIP In-Memory Cache ---
_geoip_cache: dict = {}

# Private/loopback CIDR prefixes to skip GeoIP lookups for
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "169.254.", "::1"
)

def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)

# --- Core Logic Functions ---

async def update_threat_feed():
    enable_threat_feed = os.getenv("ENABLE_THREAT_FEED", "true").lower() == "true"
    if not enable_threat_feed:
        return
    while True:
        try:
            resp = requests.get(
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                timeout=10
            )
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                new_ips = set(
                    line.strip() for line in lines
                    if not line.startswith('#') and '/' not in line
                )
                BLACKLIST_IPS.update(new_ips)
                print(f"[Threat Feed] Loaded {len(BLACKLIST_IPS)} IPs.")
        except Exception as e:
            print("[Threat Feed] Failed to pull:", e)
        await asyncio.sleep(3600)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_active_interface():
    """Finds the network interface associated with the local IP address."""
    local_ip = get_local_ip()
    if local_ip == "127.0.0.1":
        return conf.iface
        
    # On Windows, Scapy's conf.iface might be a string ID or object.
    # We try to find the one matching our local IP.
    from scapy.arch import get_if_list
    from scapy.all import get_if_addr
    
    for iface in get_if_list():
        try:
            if get_if_addr(iface) == local_ip:
                print(f"[Sniffer] Auto-detected active interface: {iface} ({local_ip})")
                return iface
        except:
            continue
    return conf.iface

COMMON_OUIS = {
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    # Apple
    "00:1c:b3": "Apple", "00:25:00": "Apple", "fc:fc:48": "Apple", "d0:81:7a": "Apple",
    "c0:a5:3e": "Apple", "a4:77:33": "Apple", "00:0a:95": "Apple", "00:10:fa": "Apple",
    "00:16:cb": "Apple", "00:17:f2": "Apple", "00:19:e3": "Apple", "00:1b:63": "Apple",
    "00:1d:4f": "Apple", "00:1e:c2": "Apple", "00:21:e9": "Apple", "00:22:41": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:24:36": "Apple", "00:25:4b": "Apple",
    "00:26:08": "Apple", "00:26:b0": "Apple", "04:0c:ce": "Apple", "04:15:52": "Apple",
    "04:26:65": "Apple", "04:4b:ed": "Apple", "04:52:f3": "Apple", "04:54:53": "Apple",
    "04:db:56": "Apple", "0c:15:39": "Apple", "0c:3e:9f": "Apple", "0c:4d:e9": "Apple",
    "0c:51:01": "Apple", "0c:74:c2": "Apple", "0c:bc:9f": "Apple", "10:1c:0c": "Apple",
    "10:40:f3": "Apple", "10:9a:dd": "Apple", "10:dd:b1": "Apple", "14:10:9f": "Apple",
    "14:20:5e": "Apple", "14:5a:05": "Apple", "14:8f:c6": "Apple", "14:99:e2": "Apple",
    "14:bd:61": "Apple", "18:20:32": "Apple", "18:af:61": "Apple", "18:e7:f4": "Apple",
    "1c:1a:df": "Apple", "1c:36:bb": "Apple", "1c:5c:f2": "Apple", "1c:ab:a7": "Apple",
    # Google
    "3c:5a:37": "Google", "f4:f5:d8": "Google", "da:a1:19": "Google", "00:1a:11": "Google",
    # Samsung
    "00:07:ab": "Samsung", "00:12:47": "Samsung", "1c:5a:3e": "Samsung", "50:50:a4": "Samsung",
    "f4:09:d4": "Samsung", "f8:cf:c5": "Samsung", "a8:06:00": "Samsung", "a8:7b:39": "Samsung",
    "ac:5f:3e": "Samsung", "b4:07:f9": "Samsung", "b8:5d:0a": "Samsung", "bc:72:b1": "Samsung",
    "c8:19:f7": "Samsung", "c8:cb:b8": "Samsung", "e4:12:18": "Samsung", "e4:e0:a6": "Samsung",
    # Intel / PC Wi-Fi
    "00:13:e8": "Intel", "00:15:00": "Intel", "00:16:ea": "Intel", "00:1c:bf": "Intel",
    "00:1d:e0": "Intel", "00:1e:64": "Intel", "00:21:5c": "Intel", "00:21:6a": "Intel",
    "00:22:fa": "Intel", "00:23:14": "Intel", "00:24:d6": "Intel", "00:24:d7": "Intel",
    "00:27:0e": "Intel", "00:27:10": "Intel", "04:0c:a5": "Intel", "04:ea:56": "Intel",
    "d4:ab:61": "Intel", "a8:71:16": "Lenovo", "aa:da:ca": "Lenovo", "70:5a:ac": "Lenovo",
    # TP-Link
    "50:3e:aa": "TP-Link", "98:de:d0": "TP-Link", "e8:94:f6": "TP-Link", "00:14:78": "TP-Link",
    "00:1d:0f": "TP-Link", "00:21:27": "TP-Link", "00:23:cd": "TP-Link", "0c:47:3d": "TP-Link",
    "0c:82:30": "TP-Link", "10:27:f5": "TP-Link", "14:cf:92": "TP-Link", "18:a6:f7": "TP-Link",
    "18:d6:c7": "TP-Link", "20:e5:2a": "TP-Link", "30:b5:c2": "TP-Link", "3c:46:d8": "TP-Link",
    # Netgear
    "00:09:5b": "Netgear", "00:14:6c": "Netgear", "00:1b:2f": "Netgear", "00:1e:2a": "Netgear",
    "00:22:3f": "Netgear", "00:24:b2": "Netgear", "00:26:f2": "Netgear", "04:a1:51": "Netgear",
    # Cisco
    "00:00:0c": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco", "00:01:64": "Cisco",
    "00:01:96": "Cisco", "00:02:4a": "Cisco", "00:02:b9": "Cisco", "00:02:fc": "Cisco",
    # Xiaomi
    "18:59:36": "Xiaomi", "28:6c:07": "Xiaomi", "34:80:b3": "Xiaomi", "50:ec:50": "Xiaomi",
    "64:09:80": "Xiaomi", "7c:1d:d9": "Xiaomi", "98:fa:e3": "Xiaomi", "ac:f7:f3": "Xiaomi",
    # Huawei
    "00:18:82": "Huawei", "00:22:a1": "Huawei", "24:df:6a": "Huawei", "28:31:52": "Huawei",
    "28:5f:db": "Huawei", "28:6e:d4": "Huawei", "30:87:30": "Huawei", "34:cd:6d": "Huawei",
    # Realtek
    "00:e0:4c": "Realtek", "52:54:00": "Realtek", "00:13:3b": "Realtek",
    # Jio / RJIL
    "54:2a:a2": "Jio", "00:0e:c6": "Jio", "c8:d7:19": "Jio", "fc:b0:de": "Jio",
    "00:54:2a": "Jio", "9c:c9:eb": "Jio", "ac:4b:c8": "Jio"
}

OUI_CACHE_FILE = os.path.join(os.path.dirname(__file__), "mac_vendors_cache.json")
_OUI_CACHE = {}
_OUI_CACHE_LOCK = threading.Lock()

def _load_oui_cache():
    global _OUI_CACHE
    if not os.path.exists(OUI_CACHE_FILE):
        _OUI_CACHE = {}
        return
    try:
        with open(OUI_CACHE_FILE, "r") as f:
            _OUI_CACHE = json.load(f)
    except Exception:
        _OUI_CACHE = {}

def _save_oui_cache():
    try:
        with open(OUI_CACHE_FILE, "w") as f:
            json.dump(_OUI_CACHE, f, indent=4)
    except Exception:
        pass

# Initialize cache
_load_oui_cache()

def _get_local_mac(local_ip):
    """Retrieves the MAC address of the local machine's active network adapter."""
    try:
        from scapy.arch import get_if_list, get_if_addr
        from scapy.all import get_if_hwaddr
        for iface in get_if_list():
            try:
                if get_if_addr(iface) == local_ip:
                    mac = get_if_hwaddr(iface).lower().replace("-", ":")
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
            except Exception:
                pass
    except Exception:
        pass
    mac_num = uuid.getnode()
    return ":".join(("%012x" % mac_num)[i:i+2] for i in range(0, 12, 2))

def _fast_ping_sweep(subnet_prefix):
    """Sends quick single-packet ping requests across the subnet to wake up idle devices and update ARP cache."""
    def _ping(ip):
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "200", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    ips = [f"{subnet_prefix}.{i}" for i in range(1, 255)]
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(_ping, ips))

def _parse_system_arp():
    """Parses system ARP table ('arp -a') on Windows/Linux as a reliable fallback/supplement."""
    devices = {}
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2})')
        for match in pattern.finditer(proc.stdout):
            ip, mac = match.group(1), match.group(2).replace("-", ":").lower()
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue
            if ip.startswith(("224.", "239.", "255.", "127.")) or ip.endswith(".255"):
                continue
            devices[ip] = mac
    except Exception as e:
        print(f"[ARP Table] Error: {e}")
    return devices

def _resolve_mac_vendor(mac):
    if not mac:
        return "Unknown Device"
    
    mac_clean = mac.lower().replace("-", ":")
    oui = ":".join(mac_clean.split(":")[:3])
    
    # 1. Check local pre-defined OUIs
    if oui in COMMON_OUIS:
        return COMMON_OUIS[oui]
        
    # 2. Check persistent cache
    with _OUI_CACHE_LOCK:
        if oui in _OUI_CACHE:
            return _OUI_CACHE[oui]
            
    # 3. Public API fallback (only once per OUI, with strict 1s timeout)
    try:
        resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=1)
        if resp.status_code == 200:
            vendor = resp.text.strip()
            for suffix in [" electronics", " technology", " co., ltd.", " co.,ltd.", " inc.", " corporation"]:
                if vendor.lower().endswith(suffix):
                    vendor = vendor[:-len(suffix)]
            vendor = vendor.strip()
            
            with _OUI_CACHE_LOCK:
                _OUI_CACHE[oui] = vendor
                _save_oui_cache()
            return vendor
    except Exception:
        pass
        
    return "Unknown Device"

def _resolve_ip_name(ip):
    local_ip = get_local_ip()
    if ip == local_ip:
        return f"{socket.gethostname()} (This PC)"
    try:
        name = socket.gethostbyaddr(ip)[0]
        # Clean up common local network domain suffixes
        for suffix in ['.local.html', '.lan', '.local', '.home', '.localdomain', '.gateway']:
            if name.lower().endswith(suffix):
                name = name[:-len(suffix)]
        if name == ip or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', name):
            return "Unknown Device"
        return name
    except Exception:
        return "Unknown Device"

def _resolve_device_profile(device):
    if device.get('is_host'):
        return device

    # Try resolving hostname via DNS
    name = _resolve_ip_name(device['ip'])
    
    # Fallback to MAC vendor if DNS fails
    if name == "Unknown Device":
        vendor = _resolve_mac_vendor(device['mac'])
        if vendor != "Unknown Device":
            name = f"{vendor} Device"
            
    device['name'] = name
    return device

def scan_network(network_range=None):
    """Scans local network for connected devices using ARP, system ARP table, ping sweep, and local host discovery."""
    local_ip = get_local_ip()
    if not network_range:
        if local_ip == "127.0.0.1":
            network_range = "192.168.1.0/24"
        else:
            network_range = ".".join(local_ip.split(".")[:-1]) + ".0/24"
            
    subnet_prefix = network_range.split(".0/")[0] if ".0/" in network_range else ".".join(local_ip.split(".")[:-1])
    print(f"[Network Scan] Scanning range: {network_range} (Subnet prefix: {subnet_prefix})")
    
    # 1. Quick ping sweep to ensure idle Wi-Fi/LAN devices wake up and update ARP cache
    _fast_ping_sweep(subnet_prefix)

    devices_dict = {}

    # 2. Scapy ARP Scan
    try:
        arp = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0, retry=1)[0]
        for _, received in result:
            ip = received.psrc
            mac = received.hwsrc.replace("-", ":").lower()
            devices_dict[ip] = {'ip': ip, 'mac': mac}
    except Exception as e:
        print(f"[Scapy ARP Scan] Warning: {e}")

    # 3. System ARP Table parsing fallback
    arp_devs = _parse_system_arp()
    for ip, mac in arp_devs.items():
        if ip.startswith(subnet_prefix + "."):
            if ip not in devices_dict:
                devices_dict[ip] = {'ip': ip, 'mac': mac}

    # 4. Host Device self-inclusion
    if local_ip != "127.0.0.1" and local_ip.startswith(subnet_prefix + "."):
        host_mac = _get_local_mac(local_ip)
        host_hostname = socket.gethostname()
        devices_dict[local_ip] = {
            'ip': local_ip,
            'mac': host_mac,
            'is_host': True,
            'name': f"{host_hostname} (This PC)"
        }

    devices_list = list(devices_dict.values())

    # 5. Resolve profiles (DNS name & MAC vendor) in parallel
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        devices_list = list(executor.map(_resolve_device_profile, devices_list))

    # 6. Sort by IP address numerically
    try:
        devices_list = sorted(devices_list, key=lambda d: ipaddress.ip_address(d['ip']))
    except Exception:
        pass

    return devices_list

# ---------------------------------------------------------------------------
# REAL-TIME PACKET SNIFFER
# ---------------------------------------------------------------------------
_packet_log_id = 0
_total_anomalies_count = 0
captured_packets_history = []
alerts_history = []
_loop: Optional[asyncio.AbstractEventLoop] = None

def _classify_packet(src_ip: str, proto: str, length: int) -> tuple:
    """Simple heuristic classifier — returns (class_label, threat_level, reasons)."""
    reasons = []
    is_anomaly = False
    threat = 0.05

    if src_ip in BLACKLIST_IPS:
        return "Anomaly", 1.0, ["Blacklisted IP Match"]

    # Heuristics
    if length > 1500:
        reasons.append("Oversized Packet")
        threat += 0.2
        is_anomaly = True
    if proto == "ICMP":
        reasons.append("ICMP Probe")
        threat += 0.1
    if proto == "TCP" and length < 40:
        reasons.append("Suspicious Short TCP")
        threat += 0.15
        is_anomaly = True

    threat = min(round(threat, 3), 0.99)
    label = "Anomaly" if is_anomaly else "Normal"
    return label, threat, reasons

def _on_packet(pkt):
    """Called by Scapy for every captured packet (runs in sniffer thread)."""
    global _packet_log_id, _total_anomalies_count, captured_packets_history, alerts_history
    if not IP in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    print(f"[Traffic] {src} -> {dst}")
    length = len(pkt)

    # Determine protocol
    if TCP in pkt:
        proto = "TCP"
    elif UDP in pkt:
        proto = "UDP"
    elif ICMP in pkt:
        proto = "ICMP"
    else:
        proto = "IP"

    label, threat, reasons = _classify_packet(src, proto, length)
    _packet_log_id += 1

    log_entry = {
        "type": "traffic_update",
        "data": {
            "id": _packet_log_id,
            "timestamp": datetime.now().isoformat(),
            "source": src,
            "destination": dst,
            "proto": proto,
            "length": length,
            "class": label,
            "threat_level": threat,
            "reasons": reasons,
        }
    }

    # Add to detection history if anomaly
    if label == "Anomaly":
        _total_anomalies_count += 1
        # Add to global alerts history
        anomaly_alert = {
            "message": f"Suspicious activity detected from {src} ({', '.join(reasons)})",
            "severity": "High" if threat > 0.7 else "Medium" if threat > 0.4 else "Low",
            "timestamp": datetime.now().isoformat(),
            "source": src,
            "threat_level": float(threat),
            "reasons": reasons
        }
        alerts_history.append(anomaly_alert)
        if len(alerts_history) > 100:
            alerts_history.pop(0)

        # Save to MongoDB anomaly collection
        if anomaly_ips_collection is not None:
            anomaly_ips_collection.update_one(
                {"ip": src},
                {"$set": {
                    "ip": src,
                    "last_seen": datetime.now().isoformat(),
                    "threat_level": float(threat),
                    "is_blocked": src in blocked_ips
                }, "$inc": {"detection_count": 1}},
                upsert=True
            )

        detections.append({
            "src_ip": src,
            "timestamp": log_entry["data"]["timestamp"],
            "threat_level": threat,
            "reasons": reasons
        })
        # Keep only last 1000 detections to save memory
        if len(detections) > 1000:
            detections.pop(0)

    # Maintain global captured packets history for newly connecting web clients
    captured_packets_history.append(log_entry["data"])
    if len(captured_packets_history) > 50:
        captured_packets_history.pop(0)

    # Persist to MongoDB if enabled
    if db_collection is not None:
        try:
            db_collection.insert_one({**log_entry["data"], "logged_at": datetime.now()})
        except Exception:
            pass

    # Schedule broadcast on the event loop (thread-safe)
    if _loop and not _loop.is_closed():
        asyncio.run_coroutine_threadsafe(manager.broadcast(log_entry), _loop)

def _run_sniffer():
    iface = os.getenv("SNIFF_IFACE", None) or get_active_interface()
    print(f"[Sniffer] Starting live capture on interface: {iface}")
    try:
        sniff(iface=iface, prn=_on_packet, store=False)
    except Exception as e:
        print(f"[Sniffer] ERROR — {e}")
        print("[Sniffer] Make sure Npcap is installed and you're running as Administrator.")

async def live_packet_sniffer():
    """Launches the blocking Scapy sniffer in a background thread."""
    global _loop
    try:
        _loop = asyncio.get_running_loop()
    except RuntimeError:
        _loop = asyncio.get_event_loop()
        
    t = threading.Thread(target=_run_sniffer, daemon=True)
    t.start()

# --- API Endpoints ---

@app.api_route("/honeypot-entry", methods=["GET", "POST"])
async def honeypot_entry(request: Request):
    """Honeypot endpoint — any access triggers a critical alert."""
    attacker_ip = request.client.host
    result = honeypot_trigger_logic(attacker_ip)

    # Broadcast real-time alert over WebSocket
    await manager.broadcast({
        "type": "alert",
        "data": {
            "message": f"Honeypot accessed by {attacker_ip}!",
            "severity": "Critical",
            "timestamp": datetime.now().isoformat()
        }
    })
    return result

@app.get("/geo-ip/{ip}")
async def get_geoip(ip: str):
    """Proxies ip-api.com and returns GeoIP data. Results are cached in memory."""
    if _is_private_ip(ip):
        # Place local IPs with slight deterministic offset so multiple devices don't stack on exact same pixel
        h = sum(ord(c) for c in ip)
        jitter_lat = ((h % 40) - 20) * 0.04
        jitter_lon = (((h * 7) % 40) - 20) * 0.04
        return {
            "lat": 20.5937 + jitter_lat,
            "lon": 78.9629 + jitter_lon,
            "country": "Private/Local",
            "org": "Internal LAN",
            "city": f"LAN ({ip})"
        }

    if ip in _geoip_cache:
        return _geoip_cache[ip]

    try:
        def _fetch():
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,org",
                timeout=3
            )
            return r.json()

        data = await asyncio.to_thread(_fetch)
        if data.get("status") == "success" and (data.get("lat") != 0 or data.get("lon") != 0):
            result = {
                "lat": float(data.get("lat", 0)),
                "lon": float(data.get("lon", 0)),
                "country": data.get("country", "Unknown"),
                "city": data.get("city", ""),
                "org": data.get("org", "Unknown"),
            }
            _geoip_cache[ip] = result
            return result
    except Exception as e:
        print(f"[GeoIP] Lookup failed for {ip}: {e}")

    # Deterministic fallback coordinate so every external IP shows on map even if offline or rate-limited
    h = sum(ord(c) for c in ip)
    fallback_lat = 15.0 + ((h * 13) % 40) - 20
    fallback_lon = ((h * 31) % 360) - 180
    fallback = {
        "lat": fallback_lat,
        "lon": fallback_lon,
        "country": "Remote Origin",
        "org": "Internet Host",
        "city": f"{ip}"
    }
    _geoip_cache[ip] = fallback
    return fallback

@app.get("/api/scan-network")
async def get_network_devices(username: str = Depends(get_current_user)):
    """API called by dashboard to list connected devices."""
    devices = scan_network() # Now detects range automatically
    return {"connected_devices": devices, "count": len(devices)}

@app.post("/token", response_model=Token)
@limiter.limit("5/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    users = load_users()
    user_data = users.get(form_data.username)
    
    if user_data and user_data.get("password") == form_data.password:
        role = user_data.get("role", "Analyst")
        access_token = create_access_token(
            data={"sub": form_data.username, "role": role},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": access_token, "token_type": "bearer", "role": role}

    # Broadcast failed-login alert
    client_ip = request.client.host if request.client else "127.0.0.1"
    await manager.broadcast({
        "type": "alert",
        "data": {
            "message": f"Failed login attempt for user '{form_data.username}' from {client_ip}",
            "severity": "High",
            "timestamp": datetime.now().isoformat(),
            "source": client_ip,
            "threat_level": 0.85,
            "reasons": ["Authentication Failure", "Brute-Force Suspect"]
        }
    })
    raise HTTPException(status_code=401, detail="Incorrect credentials")

@app.post("/register")
async def register_user(user: UserRegister):
    users = load_users()
    pending = load_pending()
    if user.username in users or user.username in pending:
        raise HTTPException(status_code=400, detail="Username already exists or is pending approval")
    
    # Store in pending instead of users
    pending[user.username] = user.dict()
    save_pending(pending)
    return {"status": "success", "message": "Registration request sent. Waiting for Head Admin approval."}

# --- Head Admin Management Endpoints ---

@app.get("/api/admin/pending-requests-count")
async def get_pending_count(user: dict = Depends(get_current_user)):
    if user.get("role") != "HeadAdmin":
        raise HTTPException(status_code=403, detail="Head Admin only")
    pending = load_pending()
    return {"count": len(pending)}

@app.get("/api/admin/pending-requests")
async def get_pending_requests(user: dict = Depends(get_current_user)):
    if user.get("role") != "HeadAdmin":
        raise HTTPException(status_code=403, detail="Head Admin only")
    return load_pending()

@app.post("/api/admin/approve-request/{username}")
async def approve_request(username: str, user: dict = Depends(get_current_user)):
    if user.get("role") != "HeadAdmin":
        raise HTTPException(status_code=403, detail="Head Admin only")
    
    pending = load_pending()
    if username not in pending:
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Move to users.json
    users = load_users()
    reg_data = pending.pop(username)
    
    # Base64 encode password as requested
    encoded_pw = base64.b64encode(reg_data["password"].encode()).decode()
    
    profile = {
        "first_name": reg_data.get("first_name"),
        "last_name": reg_data.get("last_name"),
        "email": reg_data.get("email"),
        "mobile": reg_data.get("mobile"),
        "dob": reg_data.get("dob"),
        "city": reg_data.get("city"),
        "country": reg_data.get("country"),
        "state": reg_data.get("state"),
        "org": reg_data.get("org", "IDS Security")
    }

    role = reg_data.get("role", "Analyst")

    # If it's an Admin, also store in MongoDB 'admin' collection
    if role == "Admin" and admin_collection is not None:
        admin_collection.update_one(
            {"username": username},
            {"$set": {
                "username": username,
                "password": encoded_pw,
                "role": role,
                "profile": profile,
                "id": f"ADMIN-{username}",
                "updated_at": datetime.now(),
                "verification": {
                    "is_verified": True,
                    "verified_at": datetime.now().isoformat(),
                    "verified_by": user.get("username")
                }
            }},
            upsert=True
        )

    # If it's an Analyst, store in MongoDB 'analyst' collection
    if role == "Analyst" and analyst_collection is not None:
        analyst_collection.update_one(
            {"username": username},
            {"$set": {
                "username": username,
                "password": encoded_pw,
                "role": role,
                "profile": profile,
                "id": f"ANAL-{username}",
                "updated_at": datetime.now(),
                "verification": {
                    "is_verified": True,
                    "verified_at": datetime.now().isoformat(),
                    "verified_by": user.get("username")
                }
            }},
            upsert=True
        )

    users[username] = {
        "password": reg_data["password"], # Keep original for JSON login logic for now
        "role": role,
        "profile": profile
    }
    
    save_users(users)
    save_pending(pending)
    return {"status": "success", "message": f"User {username} approved"}

@app.post("/api/admin/reject-request/{username}")
async def reject_request(username: str, user: dict = Depends(get_current_user)):
    if user.get("role") != "HeadAdmin":
        raise HTTPException(status_code=403, detail="Head Admin only")
    
    pending = load_pending()
    if username not in pending:
        raise HTTPException(status_code=404, detail="Request not found")
    
    pending.pop(username)
    save_pending(pending)
    return {"status": "success", "message": f"User {username} rejected"}

@app.get("/api/head-admin/profile")
async def get_head_profile(user: dict = Depends(get_current_user)):
    if user.get("role") != "HeadAdmin":
        raise HTTPException(status_code=403, detail="Head Admin only")
    
    username = user.get("username")
    # Try MongoDB
    if headadmin_collection is not None:
        data = headadmin_collection.find_one({"username": username})
        if data:
            return data.get("profile", {})

    return load_head_profile()

@app.post("/api/head-admin/profile")
async def update_head_profile(data: dict, user: dict = Depends(get_current_user)):
    if user.get("role") != "HeadAdmin":
        raise HTTPException(status_code=403, detail="Head Admin only")
    
    username = user.get("username")
    if headadmin_collection is not None:
        # Save to MongoDB
        headadmin_collection.update_one(
            {"username": username},
            {"$set": {
                "username": username,
                "role": "HeadAdmin",
                "profile": data, # Frontend sends the flat profile dict
                "updated_at": datetime.now(),
                "verification": {
                    "is_verified": True,
                    "verified_at": datetime.now().isoformat()
                }
            }},
            upsert=True
        )

    save_head_profile(data)
    return {"status": "success"}

@app.get("/api/admin/profile")
async def get_admin_profile(user: dict = Depends(get_current_user)):
    if user.get("role") not in ["Admin", "HeadAdmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    username = user.get("username")

    # Try to fetch from MongoDB if it's an Admin
    if user.get("role") == "Admin" and admin_collection is not None:
        data = admin_collection.find_one({"username": username})
        if data:
            p = data.get("profile", {})
            return {
                "fullname": f"{p.get('first_name', '')} {p.get('last_name', '')}".strip() or "System Admin",
                "uid": data.get("id", f"ADMIN-{username}"),
                "phone": p.get("mobile", "+1 (555) 000-0000"),
                "email": p.get("email", f"{username}@ids.security"),
                "dob": p.get("dob", "January 01, 1990")
            }

    profiles = load_admin_profiles()
    return profiles.get(username, {
        "fullname": "System Admin",
        "uid": f"ADMIN-{username}",
        "phone": "+1 (555) 000-0000",
        "email": f"{username}@ids.security",
        "dob": "January 01, 1990"
    })

@app.post("/api/admin/profile")
async def update_admin_profile(data: dict, user: dict = Depends(get_current_user)):
    if user.get("role") not in ["Admin", "HeadAdmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    username = user.get("username")

    if user.get("role") == "Admin" and admin_collection is not None:
        # Update MongoDB
        # Map frontend profile fields back to our structure
        name_parts = data.get("fullname", "").split(" ", 1)
        first = name_parts[0]
        last = name_parts[1] if len(name_parts) > 1 else ""
        
        admin_collection.update_one(
            {"username": username},
            {"$set": {
                "profile.first_name": first,
                "profile.last_name": last,
                "profile.mobile": data.get("phone"),
                "profile.email": data.get("email"),
                "profile.dob": data.get("dob"),
                "updated_at": datetime.now(),
                "verification.verified_at": datetime.now().isoformat()
            }}
        )

    profiles = load_admin_profiles()
    profiles[username] = data
    save_admin_profiles(profiles)
    return {"status": "success"}

@app.get("/api/analyst/profile")
async def get_analyst_profile(user: dict = Depends(get_current_user)):
    username = user.get("username")

    # Try MongoDB first
    if user.get("role") == "Analyst" and analyst_collection is not None:
        data = analyst_collection.find_one({"username": username})
        if data:
            p = data.get("profile", {})
            return {
                "fullname": f"{p.get('first_name', '')} {p.get('last_name', '')}".strip() or "Security Analyst",
                "uid": data.get("id", f"ANAL-{username}"),
                "phone": p.get("mobile", "+1 (000) 000-0000"),
                "email": p.get("email", f"{username}@ids.security"),
                "dob": p.get("dob", "Not Set")
            }

    profiles = load_analyst_profiles()
    return profiles.get(username, {
        "fullname": "Security Analyst",
        "uid": f"ANAL-{username}",
        "phone": "+1 (000) 000-0000",
        "email": f"{username}@ids.security",
        "dob": "Not Set"
    })

@app.post("/api/analyst/profile")
async def update_analyst_profile(data: dict, user: dict = Depends(get_current_user)):
    username = user.get("username")

    if user.get("role") == "Analyst" and analyst_collection is not None:
        name_parts = data.get("fullname", "").split(" ", 1)
        first = name_parts[0]
        last = name_parts[1] if len(name_parts) > 1 else ""
        
        analyst_collection.update_one(
            {"username": username},
            {"$set": {
                "profile.first_name": first,
                "profile.last_name": last,
                "profile.mobile": data.get("phone"),
                "profile.email": data.get("email"),
                "profile.dob": data.get("dob"),
                "updated_at": datetime.now(),
                "verification.verified_at": datetime.now().isoformat()
            }}
        )

    profiles = load_analyst_profiles()
    profiles[username] = data
    save_analyst_profiles(profiles)
    return {"status": "success"}

@app.get("/api/admin/blocked-ips")
async def get_blocked_ips(user: dict = Depends(get_current_user)):
    if user.get("role") not in ["Admin", "HeadAdmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if blocked_ips_collection is not None:
        blocked = list(blocked_ips_collection.find({}, {"_id": 0}))
        return [b["ip"] for b in blocked]
    
    return list(blocked_ips)

@app.get("/api/admin/anomaly-ips")
async def get_anomaly_ips(user: dict = Depends(get_current_user)):
    if user.get("role") not in ["Admin", "HeadAdmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if anomaly_ips_collection is not None:
        # Return detected anomalies that aren't blocked
        anomalies = list(anomaly_ips_collection.find({"is_blocked": False}, {"_id": 0}))
        for a in anomalies:
            if "last_seen" in a and "timestamp" not in a:
                a["timestamp"] = a["last_seen"]
        return anomalies

    # Fallback to in-memory detections
    unique_anomalies = {}
    for d in detections:
        src_ip = d.get("src_ip")
        if src_ip and src_ip not in blocked_ips:
            unique_anomalies[src_ip] = {
                "ip": src_ip,
                "timestamp": d.get("timestamp"),
                "threat_level": d.get("threat_level", 0)
            }
    return list(unique_anomalies.values())

@app.post("/block-ip")
@limiter.limit("5/minute")
async def block_ip(request: Request, data: IPBlockRequest, user: dict = Depends(get_current_user)):
    if user.get("role") not in ["Admin", "HeadAdmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    ip = data.ip
    if ip in blocked_ips:
        return {"status": "success", "message": "IP already blocked"}
    
    # Add firewall rule (Windows)
    try:
        subprocess.run(f"netsh advfirewall firewall add rule name=\"Block_{ip}\" dir=in action=block remoteip={ip}", shell=True)
        blocked_ips.add(ip)
        
        # Persistent block in MongoDB
        if blocked_ips_collection is not None:
            blocked_ips_collection.update_one(
                {"ip": ip},
                {"$set": {"ip": ip, "blocked_at": datetime.now(), "blocked_by": user.get("username")}},
                upsert=True
            )
        # Update anomaly collection to mark as blocked
        if anomaly_ips_collection is not None:
            anomaly_ips_collection.update_one({"ip": ip}, {"$set": {"is_blocked": True}})

        return {"status": "success", "message": f"IP {ip} blocked successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/unblock-ip")
async def unblock_ip(data: IPBlockRequest, user: dict = Depends(get_current_user)):
    if user.get("role") not in ["Admin", "HeadAdmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    ip = data.ip
    if ip not in blocked_ips:
        return {"status": "success", "message": "IP not in blocked list"}
    
    # Remove firewall rule
    try:
        subprocess.run(f"netsh advfirewall firewall delete rule name=\"Block_{ip}\"", shell=True)
        if ip in blocked_ips:
            blocked_ips.remove(ip)
        
        # Remove from MongoDB blocked collection
        if blocked_ips_collection is not None:
            blocked_ips_collection.delete_one({"ip": ip})
        
        # Update anomaly collection to mark as unblocked
        if anomaly_ips_collection is not None:
            anomaly_ips_collection.update_one({"ip": ip}, {"$set": {"is_blocked": False}})

        return {"status": "success", "message": f"IP {ip} unblocked successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws/traffic")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Immediately broadcast current stats and recent log history upon connection
        initial_payload = {
            "type": "initial_state",
            "data": {
                "total_packets": _packet_log_id,
                "total_anomalies": _total_anomalies_count,
                "total_alerts": len(alerts_history),
                "history": captured_packets_history,
                "alerts": alerts_history
            }
        }
        await websocket.send_json(initial_payload)
        
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- Startup Event ---
@app.on_event("startup")
async def startup_event():
    # Sync blocked IPs from MongoDB if available
    if blocked_ips_collection is not None:
        try:
            stored_blocks = list(blocked_ips_collection.find({}, {"ip": 1}))
            for b in stored_blocks:
                blocked_ips.add(b["ip"])
            print(f"[Startup] Synced {len(stored_blocks)} blocked IPs from MongoDB.")
        except Exception as e:
            print(f"[Startup] Failed to sync blocked IPs: {e}")

    # Use a different port for honeypot if default 2222 is busy
    os.environ["HONEYPOT_PORT"] = os.getenv("HONEYPOT_PORT", "2223")
    asyncio.create_task(live_packet_sniffer())
    asyncio.create_task(update_threat_feed())
    asyncio.create_task(start_honeypot_service(manager))

@app.get("/health")
async def health_check():
    return {
        "status": "online",
        "sniffer": "active",
        "interface": get_active_interface(),
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    # Start on 0.0.0.0:8000
    uvicorn.run(app, host="0.0.0.0", port=8000)