from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
from scapy.all import PcapReader, TCP, IP

app = Flask(__name__)
app.secret_key = "ids_secret_key_fyp"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# --- Hardcoded credentials ---
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# --- IDS Configuration ---
TARGET_IP = "192.168.56.102"       # Simulated student device IP
HIGH_TRAFFIC_RATE_THRESHOLD = 5.0  # Packets per second considered high for this lab IDS
HIGH_TRAFFIC_PACKET_COUNT_THRESHOLD = 150  # Total target packets considered high volume
PORT_SCAN_THRESHOLD = 50           # Unique TCP ports considered port scan


def analyze_pcap(pcap_source):
    """
    Reads a .pcap file path or uploaded file stream and performs IDS analysis.
    Returns a dict with traffic_summary and alerts.
    """
    with PcapReader(pcap_source) as pcap_reader:
        packets = list(pcap_reader)

    packet_times = [float(pkt.time) for pkt in packets if hasattr(pkt, "time")]
    capture_duration = 0.0
    if len(packet_times) >= 2:
        capture_duration = max(packet_times) - min(packet_times)

    # Packet rate is calculated as packets divided by capture duration.
    # A minimum analysis window of 1 second avoids division by zero for very short
    # captures while keeping the result easy to explain in an FYP demonstration.
    rate_duration = max(capture_duration, 1.0)

    ip_packet_count = {}
    ip_tcp_ports = {}
    ip_packet_times = {}

    # --- Process packets ---
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src

            # Count packets per IP (for summary display)
            ip_packet_count[src_ip] = ip_packet_count.get(src_ip, 0) + 1
            ip_packet_times.setdefault(src_ip, []).append(float(pkt.time))

            # Track TCP ports
            if TCP in pkt:
                dst_port = pkt[TCP].dport
                ip_tcp_ports.setdefault(src_ip, set()).add(dst_port)

    # --- Build traffic summary (same UI table, with packet rate added) ---
    traffic_summary = []
    for ip, count in sorted(ip_packet_count.items(), key=lambda x: x[1], reverse=True):
        unique_ports = len(ip_tcp_ports.get(ip, set()))
        ip_times = ip_packet_times.get(ip, [])
        ip_activity_duration = 0.0
        if len(ip_times) >= 2:
            ip_activity_duration = max(ip_times) - min(ip_times)
        packet_rate = count / max(ip_activity_duration, 1.0)
        traffic_summary.append({
            "ip": ip,
            "packet_count": count,
            "packet_rate": round(packet_rate, 2),
            "unique_tcp_ports": unique_ports,
        })

    # --- IDS Detection (ONLY target IP) ---
    alerts = []

    target_count = ip_packet_count.get(TARGET_IP, 0)
    target_ports = ip_tcp_ports.get(TARGET_IP, set())
    target_times = ip_packet_times.get(TARGET_IP, [])
    target_activity_duration = 0.0
    if len(target_times) >= 2:
        target_activity_duration = max(target_times) - min(target_times)

    # Packet-count calculation:
    # target_count is the number of packets sent by the monitored TARGET_IP.
    # This captures total traffic volume, even if the traffic is not extremely fast.
    #
    # Packet-rate calculation:
    # target_activity_duration uses only the monitored host's activity window:
    # first TARGET_IP packet to last TARGET_IP packet. This prevents attack
    # traffic from being diluted when Wireshark keeps capturing unrelated idle
    # time after the attack has stopped.
    target_rate_duration = max(target_activity_duration, 1.0)
    target_packet_rate = target_count / target_rate_duration

    # High traffic detection uses two simple indicators:
    # 1. Packet rate detects short, intense bursts of traffic.
    # 2. Packet count detects large total traffic volume across the capture.
    # Using both keeps the IDS understandable for an FYP while reducing the chance
    # that a high-volume attack is missed only because its rate is averaged down.
    high_rate_detected = target_packet_rate > HIGH_TRAFFIC_RATE_THRESHOLD
    high_count_detected = target_count > HIGH_TRAFFIC_PACKET_COUNT_THRESHOLD

    if high_rate_detected or high_count_detected:
        detection_reasons = []
        if high_rate_detected:
            detection_reasons.append(
                f"rate {target_packet_rate:.2f} packets/sec > "
                f"{HIGH_TRAFFIC_RATE_THRESHOLD:.2f} packets/sec"
            )
        if high_count_detected:
            detection_reasons.append(
                f"count {target_count} packets > "
                f"{HIGH_TRAFFIC_PACKET_COUNT_THRESHOLD} packets"
            )

        alerts.append({
            "type": "HIGH TRAFFIC",
            "severity": "high",
            "ip": TARGET_IP,
            "detail": (
                f"{target_packet_rate:.2f} packets/sec detected from "
                f"{target_count} packets over {target_activity_duration:.2f} seconds "
                f"(trigger: {' or '.join(detection_reasons)})"
            ),
            "icon": "!"
        })

    # Port scan detection
    if len(target_ports) > PORT_SCAN_THRESHOLD:
        alerts.append({
            "type": "PORT SCAN",
            "severity": "critical",
            "ip": TARGET_IP,
            "detail": f"{len(target_ports)} unique TCP ports accessed (threshold: {PORT_SCAN_THRESHOLD})",
            "icon": "!"
        })

    # If no alerts
    status_message = None

    if not alerts:
        status_message = "No suspicious activity detected."

    return {
        "traffic_summary": traffic_summary,
        "alerts": alerts,
        "status_message": status_message,
        "total_packets": len(packets),
        "total_ips": len(ip_packet_count),
        "capture_duration": round(capture_duration, 2),
        "packet_rate": round(len(packets) / rate_duration, 2),
        "detection_threshold": HIGH_TRAFFIC_RATE_THRESHOLD,
        "packet_count_threshold": HIGH_TRAFFIC_PACKET_COUNT_THRESHOLD,
        "target_ip": TARGET_IP,
        "target_packet_count": target_count,
        "target_activity_duration": round(target_activity_duration, 2),
        "target_packet_rate": round(target_packet_rate, 2),
        "target_unique_ports": len(target_ports),
        }


# --- Routes ---------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():
    if "logged_in" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "logged_in" not in session:
        return redirect(url_for("login"))

    results = None
    error = None

    if request.method == "POST":
        if "pcap_file" not in request.files:
            error = "No file part in the request."
        else:
            f = request.files["pcap_file"]
            if f.filename == "":
                error = "No file selected."
            elif not f.filename.lower().endswith(".pcap"):
                error = "Only .pcap files are supported."
            else:
                try:
                    f.stream.seek(0)
                    results = analyze_pcap(f.stream)
                except Exception as e:
                    error = f"Error analyzing file: {str(e)}"

    return render_template("dashboard.html", results=results, error=error,
                           username=session.get("username", "Admin"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
