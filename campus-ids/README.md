# Campus IDS - Final Year Project
### Network Intrusion Detection System (Flask + Scapy)

---

## Project Structure

```
ids_app/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── templates/
│   ├── login.html          # Login page
│   └── dashboard.html      # Dashboard and results page
└── uploads/                # Existing upload folder retained for project structure
```

---

## How to Run

### 1. Install Python 3.8+

```bash
python --version
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the App

```bash
python app.py
```

### 5. Open in Browser

```text
http://127.0.0.1:5000
```

---

## Login Credentials

| Field    | Value      |
|----------|------------|
| Username | `admin`    |
| Password | `admin123` |

---

## IDS Detection Rules

| Rule         | Condition                                                       | Severity |
|--------------|-----------------------------------------------------------------|----------|
| High Traffic | Target IP sends more than 5 packets/second OR more than 150 packets | HIGH     |
| Port Scan    | Target IP accesses more than 50 TCP ports                       | CRITICAL |

The monitored target IP is `192.168.56.102`, representing the student/victim VM.
You can change this in `app.py` by editing the `TARGET_IP` variable.

The high-traffic rule uses two simple metrics: target packet rate and target
packet count.

```text
target_activity_duration = last_TARGET_IP_packet_time - first_TARGET_IP_packet_time
packet_rate = target_packet_count / target_activity_duration
packet_count = total packets sent by TARGET_IP
```

This is more defensible than a fixed packet count because the detection decision
now includes the time period of the monitored host's activity. It avoids diluting
the attack rate when Wireshark continues capturing idle or unrelated traffic
after the attack ends.

For this controlled undergraduate VM lab, `5 packets/second` is used as a simple
educational threshold. Normal sample traffic should remain below it, while ping
floods, repeated connection attempts, or similar attack demonstrations should
exceed it. The secondary `150 packets` count threshold acts as a simple volume
backup, so the IDS can still flag a large amount of target traffic even when the
rate is less bursty. This project is an educational IDS prototype, not an
enterprise IDS.

---

## Testing With Wireshark Captures

### Normal Traffic Capture

1. Start the monitored VM using IP `192.168.56.102`.
2. Start Wireshark on the adapter used by the VM.
3. Capture 30 to 60 seconds of ordinary activity, such as light browsing, DNS
   lookups, or a few manual pings.
4. Save the capture as `normal_test.pcap`.
5. Upload it to the Flask dashboard. The target packet rate should normally stay
   below `5 packets/second` and the target packet count should stay below `150`,
   so no high-traffic alert should appear.

### Attack Traffic Capture

1. Start Wireshark on the same adapter before launching the attack.
2. From the monitored VM (`192.168.56.102`), generate sustained traffic for about
   20 to 30 seconds. Examples include a fast ping test or repeated connection
   attempts to another lab host.
3. Save the capture as `attack_test.pcap`.
4. Upload it to the Flask dashboard. If the monitored VM sends more than
   `5 packets/second` or more than `150` packets, a high-traffic alert should
   appear.

For port-scan testing, use a scan that makes the monitored VM contact more than
50 different TCP destination ports in the same capture.

---

## Dependencies

- Flask
- Scapy

---

Built for FYP - Campus Network Intrusion Detection System.
