import asyncio
import os
from datetime import datetime

# NOTE: No Flask import — this runs inside a FastAPI app.


async def handle_honeypot_connection(reader, writer, connection_manager):
    """Handles raw TCP connections to the honeypot decoy port."""
    addr = writer.get_extra_info('peername')
    ip = addr[0] if addr else "unknown"

    # Send a realistic decoy SSH banner
    banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
    writer.write(banner)
    await writer.drain()

    timestamp = datetime.now().isoformat()

    # Broadcast traffic_update with max severity
    alert_log = {
        "type": "traffic_update",
        "data": {
            "id": int(datetime.now().timestamp() * 1000),
            "timestamp": timestamp,
            "source": ip,
            "destination": "HONEYPOT_DECOY",
            "proto": "TCP",
            "length": 0,
            "class": "Anomaly",
            "threat_level": 1.0,
            "reasons": ["Deception Triggered", "Unauthorized Port Scan", "Decoy Connection"]
        }
    }
    await connection_manager.broadcast(alert_log)

    # Broadcast a separate critical alert message
    await connection_manager.broadcast({
        "type": "alert",
        "data": {
            "message": f"Critical: Honeypot decoy SSH port accessed by {ip}!",
            "severity": "Critical",
            "timestamp": timestamp,
            "source": ip,
            "threat_level": 1.0,
            "reasons": ["Honeypot Decoy Breach", "Unauthorized Service Probing"]
        }
    })

    # Optionally persist to MongoDB
    _persist_honeypot_event(ip, timestamp)

    # Give attacker a few seconds to interact, then close
    try:
        await asyncio.wait_for(reader.read(100), timeout=5.0)
    except (asyncio.TimeoutError, Exception):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _persist_honeypot_event(ip: str, timestamp: str):
    """Writes honeypot hit to MongoDB if enabled."""
    enable_mongo = os.getenv("ENABLE_MONGODB", "false").lower() == "true"
    if not enable_mongo:
        return
    try:
        from pymongo import MongoClient
        client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"), serverSelectionTimeoutMS=2000)
        col = client["ids_db"]["honeypot_events"]
        col.insert_one({"source_ip": ip, "timestamp": timestamp, "event": "Decoy SSH Access"})
        client.close()
    except Exception as e:
        print(f"[Honeypot MongoDB] Write failed: {e}")


async def start_honeypot_service(connection_manager):
    """Starts the async TCP honeypot server."""
    enable_honeypot = os.getenv("ENABLE_HONEYPOT", "true").lower() == "true"
    if not enable_honeypot:
        print("[Honeypot] Disabled via ENABLE_HONEYPOT=false")
        return

    port = int(os.getenv("HONEYPOT_PORT", "2222"))
    try:
        server = await asyncio.start_server(
            lambda r, w: handle_honeypot_connection(r, w, connection_manager),
            '0.0.0.0', port
        )
        print(f"[Honeypot] Decoy SSH listening on port {port}")
        async with server:
            await server.serve_forever()
    except Exception as e:
        print(f"[Honeypot] Failed to start on port {port}: {e}")


def honeypot_trigger_logic(attacker_ip: str = "unknown"):
    """
    Called when the /honeypot-entry HTTP endpoint is accessed.
    Logs the intrusion and returns a fake 403 response.
    """
    print(f"[Honeypot] HTTP endpoint accessed by: {attacker_ip}")
    _persist_honeypot_event(attacker_ip, datetime.now().isoformat())
    return {"detail": "Access Denied"}, 403