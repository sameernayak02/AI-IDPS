import os
import time
import math
import json
import warnings
from collections import defaultdict, deque, Counter
import numpy as np
import joblib

warnings.filterwarnings("ignore")

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODELS_DIR, "ids_model.joblib")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")

class MLEngine:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.metadata = {}
        self.is_loaded = False
        
        # Sliding rate tracker per source IP (IP -> deque of timestamps in last 2.0s)
        self._ip_packet_timestamps = defaultdict(lambda: deque(maxlen=200))
        self.load_model()

    def load_model(self):
        """Loads pre-trained Random Forest model, Scaler, and Metadata."""
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                self.model = joblib.load(MODEL_PATH)
                if hasattr(self.model, "n_jobs"):
                    self.model.n_jobs = 1  # Use single thread for instant micro-inference
                self.scaler = joblib.load(SCALER_PATH)
                if os.path.exists(METADATA_PATH):
                    with open(METADATA_PATH, "r") as f:
                        self.metadata = json.load(f)
                self.is_loaded = True
                print(f"[ML Engine] Pre-trained '{self.metadata.get('model_name', 'Random Forest')}' loaded successfully.")
                print(f"[ML Engine] Model Accuracy: {self.metadata.get('metrics', {}).get('accuracy', 0)}%")
            else:
                print("[ML Engine] Model files not found in backend/models. Running in fallback mode.")
                self.is_loaded = False
        except Exception as e:
            print(f"[ML Engine] Error loading model: {e}")
            self.is_loaded = False

    def get_model_info(self) -> dict:
        """Returns loaded model metrics, metadata, and confusion matrix for viva demonstration."""
        if not self.is_loaded:
            return {
                "status": "not_loaded",
                "message": "Model not loaded. Train using backend/train_model.py"
            }
        return {
            "status": "active",
            "model_name": self.metadata.get("model_name", "Random Forest Classifier"),
            "dataset_source": self.metadata.get("dataset_source", "CICIDS2017 & NSL-KDD Benchmarks"),
            "training_timestamp": self.metadata.get("training_timestamp", ""),
            "total_samples": self.metadata.get("total_samples", 17500),
            "features": self.metadata.get("features", []),
            "target_classes": self.metadata.get("target_classes", {}),
            "metrics": self.metadata.get("metrics", {}),
            "feature_importances": self.metadata.get("feature_importances", {}),
            "confusion_matrix": self.metadata.get("confusion_matrix", {}),
            "per_class_metrics": self.metadata.get("per_class_metrics", {})
        }

    def _calculate_entropy(self, payload_bytes: bytes) -> float:
        """Calculates Shannon entropy (0.0 to 8.0) of packet payload."""
        if not payload_bytes:
            return 0.0
        counts = Counter(payload_bytes)
        total_len = len(payload_bytes)
        entropy = 0.0
        for count in counts.values():
            p = count / total_len
            entropy -= p * math.log2(p)
        return round(float(entropy), 3)

    def _track_packet_rate(self, src_ip: str) -> float:
        """Calculates instantaneous packet rate (packets per second) for the source IP."""
        now = time.time()
        dq = self._ip_packet_timestamps[src_ip]
        dq.append(now)

        # Remove entries older than 2 seconds
        while dq and (now - dq[0]) > 2.0:
            dq.popleft()

        count = len(dq)
        if count <= 1:
            return 1.0
        time_span = max(now - dq[0], 0.05)
        rate = count / time_span
        return round(float(rate), 2)

    def extract_features(self, pkt, src_ip: str, proto: str, length: int) -> tuple:
        """
        Extracts the 13 feature dimensions expected by the trained ML pipeline:
        [length, protocol_code, syn, ack, fin, rst, header_len, ttl, win_size, dst_port, rate, has_payload, entropy]
        """
        # 1. Length
        pkt_len = float(length)

        # 2. Protocol code (TCP=6, UDP=17, ICMP=1)
        proto_code = 6.0 if proto == "TCP" else (17.0 if proto == "UDP" else (1.0 if proto == "ICMP" else 0.0))

        # 3-6. TCP Flags
        syn, ack, fin, rst = 0.0, 0.0, 0.0, 0.0
        header_len = 28.0
        win_size = 0.0
        dst_port = 80.0

        if proto == "TCP":
            try:
                # Check Scapy TCP layer
                tcp_layer = pkt.getlayer("TCP") if hasattr(pkt, "getlayer") else None
                if tcp_layer:
                    flags = int(tcp_layer.flags)
                    syn = 1.0 if (flags & 0x02) else 0.0
                    ack = 1.0 if (flags & 0x10) else 0.0
                    fin = 1.0 if (flags & 0x01) else 0.0
                    rst = 1.0 if (flags & 0x04) else 0.0
                    win_size = float(getattr(tcp_layer, "window", 0))
                    dst_port = float(getattr(tcp_layer, "dport", 80))
                    header_len = 40.0
            except Exception:
                pass
        elif proto == "UDP":
            try:
                udp_layer = pkt.getlayer("UDP") if hasattr(pkt, "getlayer") else None
                if udp_layer:
                    dst_port = float(getattr(udp_layer, "dport", 53))
                    header_len = 28.0
            except Exception:
                pass

        # 7-8. IP header details (TTL)
        ttl = 64.0
        try:
            ip_layer = pkt.getlayer("IP") if hasattr(pkt, "getlayer") else None
            if ip_layer:
                ttl = float(getattr(ip_layer, "ttl", 64))
        except Exception:
            pass

        # 9. Packet Rate
        rate = self._track_packet_rate(src_ip)

        # 10-11. Payload & Shannon Entropy
        has_payload = 0.0
        entropy = 0.0
        try:
            raw_layer = pkt.getlayer("Raw") if hasattr(pkt, "getlayer") else None
            if raw_layer and hasattr(raw_layer, "load") and raw_layer.load:
                has_payload = 1.0
                entropy = self._calculate_entropy(raw_layer.load)
        except Exception:
            pass

        feature_vector = np.array([
            pkt_len, proto_code, syn, ack, fin, rst, header_len, ttl,
            win_size, dst_port, rate, has_payload, entropy
        ], dtype=np.float32).reshape(1, -1)

        raw_dict = {
            "length": pkt_len,
            "protocol": proto,
            "syn": bool(syn),
            "ack": bool(ack),
            "fin": bool(fin),
            "rst": bool(rst),
            "dst_port": int(dst_port),
            "packet_rate": rate,
            "has_payload": bool(has_payload),
            "entropy": entropy
        }

        return feature_vector, raw_dict

    def classify_packet(self, pkt, src_ip: str, proto: str, length: int) -> tuple:
        """
        Runs ML classification on an intercepted network packet.
        Returns:
            label: "Normal" or "Anomaly"
            threat_level: float (0.0 to 1.0)
            attack_type: "Normal" or attack name (e.g. "DDoS / DoS Attack")
            reasons: List of explanatory reasons (Explainable AI)
        """
        feature_vector, raw_dict = self.extract_features(pkt, src_ip, proto, length)
        reasons = []

        if not self.is_loaded or self.model is None or self.scaler is None:
            # Fallback heuristic if model files are unreadable
            threat = 0.05
            is_anomaly = False
            if length > 1500:
                threat += 0.35
                reasons.append("Oversized Frame (>1500B)")
                is_anomaly = True
            if proto == "ICMP":
                threat += 0.25
                reasons.append("ICMP Echo/Ping Probe")
            return ("Anomaly" if is_anomaly else "Normal"), min(threat, 0.95), "Generic Anomaly", reasons

        try:
            # Scale features
            scaled_features = self.scaler.transform(feature_vector)

            # Predict probabilities
            probs = self.model.predict_proba(scaled_features)[0]
            pred_class_idx = int(np.argmax(probs))
            confidence = float(probs[pred_class_idx])

            attack_classes = self.metadata.get("target_classes", {
                "0": "Normal",
                "1": "DDoS / DoS Attack",
                "2": "Port Scan (Reconnaissance)",
                "3": "Brute Force Attack",
                "4": "Malformed / Injection"
            })

            attack_name = attack_classes.get(str(pred_class_idx), "Anomaly")

            # Determine label and threat score
            if pred_class_idx == 0:
                # Normal traffic
                label = "Normal"
                threat_level = round(float(1.0 - probs[0]) * 0.25, 3) # Keep normal threat low (0.01 - 0.20)
                threat_level = max(0.02, min(threat_level, 0.20))
                reasons.append("Verified benign pattern (Confidence: {:.1f}%)".format(confidence * 100))
            else:
                # Malicious traffic
                label = "Anomaly"
                threat_level = round(float(confidence), 3)
                threat_level = max(0.70, min(threat_level, 0.99)) # Threat >= 0.70

                reasons.append(f"AI Detected: {attack_name} ({confidence * 100:.1f}% confidence)")

                # Detailed Explainable AI reasons based on active features
                if raw_dict["packet_rate"] > 35:
                    reasons.append(f"High traffic frequency ({raw_dict['packet_rate']:.1f} pkts/s)")
                if raw_dict["syn"] and not raw_dict["ack"]:
                    reasons.append("SYN probe with no ACK")
                if raw_dict["entropy"] > 6.0:
                    reasons.append(f"High payload entropy ({raw_dict['entropy']:.2f})")
                if raw_dict["dst_port"] in [22, 21, 3389]:
                    reasons.append(f"Sensitive service port targeted ({raw_dict['dst_port']})")

            return label, threat_level, attack_name, reasons

        except Exception as e:
            print(f"[ML Engine] Inference error: {e}")
            return "Normal", 0.05, "Normal", ["Inference Fallback"]

# Global Singleton Instance
ml_engine = MLEngine()
