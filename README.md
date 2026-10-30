# AI-Powered Intrusion Detection and Prevention System (IDPS)

An enterprise-grade, real-time cybersecurity solution combining machine learning anomaly detection, live packet sniffing, autonomous firewall mitigation, and multi-protocol network device tracking across both traditional Wi-Fi/LAN networks and mobile hotspots.

---

## 🚀 Key Features

* **⚡ Real-Time Packet Sniffing:** Powered by Scapy to capture live raw network frames, extract protocol headers (IP, TCP, UDP, ICMP), and stream telemetry via WebSockets.
* **🧠 Machine Learning Anomaly Detection:** Pre-trained Random Forest Classifier analyzing live traffic flow features with real-time threat-level scoring.
* **🛡️ Autonomous Intrusion Prevention (IPS):** Dynamically adds and removes Windows Defender Firewall rules to neutralize high-risk anomalies automatically.
* **📱 Multi-Protocol Network Device Tracker:** Discovers all connected LAN, Wi-Fi, and **Mobile Hotspot** devices with intelligent hostname, vendor, and OS resolution.
* **🗺️ Real-Time Cyber Threat Map:** Interactive global Leaflet map geolocating remote IPs with deterministic local subnet visualization.
* **🍯 Integrated Honeypot Decoy:** Trap services capturing unauthorized probes and scanning attempts.
* **🔐 Role-Based Access Control (RBAC):** Tiered authentication system supporting Head Admin, Admin, and Analyst roles with persistent MongoDB / local profile storage.

---

## 📡 Network Device Tracker (Wi-Fi & Mobile Hotspot)

Standard network scanners fail to resolve hostnames on **Mobile Hotspots** because mobile operating systems (Android/iOS) do not run a queryable local reverse DNS (rDNS/PTR) server. 

This IDPS includes a **multi-tiered device resolution pipeline** that resolves hostnames across both home/office routers and tethered mobile hotspots:

```
                     ┌──────────────────────────────────────────────┐
                     │          Device IP Detected on LAN           │
                     └──────────────────────┬───────────────────────┘
                                            │
               ┌────────────────────────────┴───────────────────────────┐
               ▼                                                        ▼
    [1. Hotspot Gateway Check]                                [2. DNS Reverse Lookup]
    Matches Hotspot Host (Android/iOS)                        socket.gethostbyaddr()
               │ (if not gateway)                                       │ (if fails)
               ▼                                                        ▼
    [3. Unicast mDNS Probe (UDP 5353)]                       [4. NetBIOS Name Query (UDP 137)]
    Resolves Apple (iPhone/Mac), Linux/Avahi                 Resolves Windows Laptops/PCs
               │ (if no response)                                       │ (if no response)
               ▼                                                        ▼
    [5. Fast Port Fingerprint]                               [6. Hardware OUI & Private MAC]
    Apple (62078), Cast (8008), WSD (5357)                   Checks 225+ mobile brands or Private MAC
```

1. **Hotspot Host Detection:** Automatically interrogates the system routing table to isolate the default gateway (e.g. `192.168.43.1` on Android, `172.20.10.1` on iOS) and badges it as `HOTSPOT / GATEWAY` with phone model inference.
2. **Unicast mDNS Probing (`UDP 5353`):** Sends direct reverse PTR requests to query Apple devices (iPhones, iPads, MacBooks) and Linux/Avahi clients for user-configured device names (e.g. `Sameer-iPhone`).
3. **Unicast NetBIOS Queries (`UDP 137`):** Direct Node Status query packets to target IPs to extract Windows computer names (e.g. `LAPTOP-5VKBCI26`).
4. **Fast Port Fingerprinting:** Inspects characteristic listening ports (Apple Lockdown `62078`, Google Cast `8008`/`8009`, Android ADB `5555`, Windows WSD `5357`).
5. **IEEE 802 Private MAC Detection:** Identifies randomized MAC addresses (`int(mac[0], 16) & 2 != 0`) enforced by modern Android/iOS privacy settings and labels them accurately as `Mobile Device (Private MAC)`.
6. **Extensive Hardware OUI Database:** 225+ local pre-cached vendor signatures (Apple, Samsung, OnePlus, Xiaomi, Oppo, Vivo, Realme, Motorola, Google Pixel, Intel, Lenovo, Asus, etc.) with online API fallback.

---

## 🛠️ How to Run the Project

### Prerequisites
* **Python 3.10+** (64-bit recommended)
* **Npcap** or **WinPcap** installed on Windows (with *WinPcap API-compatible mode* enabled for Scapy raw sniffing)
* Administrator terminal permissions (required for raw packet capture and Windows Firewall management)

---

### (1) Backend Setup
1. Open a terminal (run as Administrator on Windows) and navigate to the `backend` directory:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the FastAPI backend server:
   ```bash
   python app.py
   ```
   > The API server will be available at: `http://localhost:8000`  
   > Interactive API docs (Swagger): `http://localhost:8000/docs`

---

### (2) Frontend Setup
1. Open a new terminal and navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```
2. Start a local HTTP server:
   ```bash
   python -m http.server 8080
   ```
3. Open your browser and access:
   * **Local Dashboard:** `http://localhost:8080`
   * **Hosted Dashboard:** `https://ai-idps-dashboard.vercel.app/`

---

## 🔌 Core API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/scan-network` | Triggers multi-protocol ARP, mDNS, NetBIOS & Hotspot device discovery |
| `WS` | `/ws/traffic` | Real-time WebSocket streaming live captured packets & AI threat evaluations |
| `POST` | `/api/block-ip` | Blocks malicious IP via Windows Defender Firewall |
| `POST` | `/api/unblock-ip` | Removes IP from Windows Defender Firewall blocklist |
| `GET` | `/api/model-info` | Returns Machine Learning engine metrics and training statistics |
| `POST` | `/api/token` | OAuth2 password bearer token authentication |
| `POST` | `/api/register` | User and analyst registration endpoint |

---

## 💡 Practical Tip for Mobile Hotspot Testing

Modern Android and iOS devices randomize their MAC address when connecting to any network:
* If you want your phone's exact manufacturer name (e.g. `Samsung Phone`, `Apple iPhone`) permanently shown in the Network Device Tracker, go to:
  * **Phone Settings** &rarr; **Wi-Fi / Network** &rarr; tap your connection gear icon &rarr; **Privacy / MAC type** &rarr; select **"Use Device / Phone MAC"**.
