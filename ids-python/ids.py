import json
import logging
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, Raw, conf

# Core Configuration (IDS Thresholds)
PORT_SCAN_THRESHOLD = 10
UDP_FLOOD_THRESHOLD = 50           
DETECTION_WINDOW_SECS = 5
ALERT_LOG_PATH = "ids_alerts.json"

# Logging Configuration for Structured JSON Output
logging.basicConfig(
    filename=ALERT_LOG_PATH,
    level=logging.INFO,
    format='%(message)s'
)

SUSPICIOUS_PORTS_IOC = [4444, 5555, 6666, 31337, 12345]

# Stateful Memory Trackers
tcp_syn_tracker = defaultdict(list)
udp_rate_tracker = defaultdict(list)  

def log_structured_alert(event_type, source_ip, details):
    alert_event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event_type,
        "source_ip": source_ip,
        "details": details
    }
    logging.info(json.dumps(alert_event))

def packet_handler(pkt):
    if ARP in pkt and pkt[ARP].op == 2:
        print(f"[ALERT] ARP SPOOFING DETECTED: {pkt[ARP].hwsrc} claims to be {pkt[ARP].psrc}")

    if IP not in pkt:
        return

    source_ip = pkt[IP].src
    dest_ip = pkt[IP].dst
    
    current_time = datetime.now()
    time_threshold = current_time - timedelta(seconds=DETECTION_WINDOW_SECS)

    if ICMP in pkt and Raw in pkt:
        if len(pkt[Raw].load) > 100:
            print(f"[WARNING] SUSPICIOUS ICMP: Large payload ({len(pkt[Raw].load)} bytes) from {source_ip}")

    if TCP in pkt:
        dest_port = pkt[TCP].dport
        flags = pkt[TCP].flags
        
        # Stateful Port Scan Detection
        if flags == "S":
            tcp_syn_tracker[source_ip].append((current_time, dest_port))
            
            tcp_syn_tracker[source_ip] = [
                (ts, port) for ts, port in tcp_syn_tracker[source_ip] if ts > time_threshold
            ]
            
            unique_ports = {port for ts, port in tcp_syn_tracker[source_ip]}
            
            if len(unique_ports) > PORT_SCAN_THRESHOLD:
                alert_details = f"Attempted connections to {len(unique_ports)} unique ports."
                print(f"\n[ALERT] PORT SCAN SIGNATURE: Host {source_ip} triggered threshold. {alert_details}")
                log_structured_alert("Port Scan", source_ip, alert_details)
        
        if dest_port in SUSPICIOUS_PORTS_IOC:
            print(f"[CRITICAL ALERT] Known malware IOC port hit ({dest_port}) from {source_ip}")
            
        print(f"[TCP] {source_ip}:{pkt[TCP].sport} -> {dest_ip}:{dest_port}")

    elif UDP in pkt:
        dest_port = pkt[UDP].dport
        
        udp_rate_tracker[source_ip].append(current_time)
        udp_rate_tracker[source_ip] = [ts for ts in udp_rate_tracker[source_ip] if ts > time_threshold]
        
        if len(udp_rate_tracker[source_ip]) > UDP_FLOOD_THRESHOLD:
            alert_details = f"Sent {len(udp_rate_tracker[source_ip])} UDP packets."
            print(f"\n[ALERT] UDP FLOOD SIGNATURE: Host {source_ip} triggered threshold. {alert_details}")
            log_structured_alert("UDP Flood", source_ip, alert_details)
            
        print(f"[UDP] {source_ip} -> {dest_ip}:{dest_port}")   

def main():
    parser = argparse.ArgumentParser(description="Professional Lightweight Network IDS")
    parser.add_argument("-i", "--interface", help="Specify the network interface to sniff on", default=None)
    parser.add_argument("-l", "--list", help="List all available network interfaces", action="store_true")
    args = parser.parse_args()

    if args.list:
        print("[-] Available Network Interfaces:")
        print(conf.ifaces)
        return

    selected_interface = args.interface
    print("[-] Launching Network Intrusion Detection System...")
    print(f"[-] Sniffing interface: {selected_interface if selected_interface else 'Default OS Interface'}")
    print(f"[-] Structured logs saving to: '{ALERT_LOG_PATH}'\n")
    
    try:
        sniff(iface=selected_interface, prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\n[-] Sniffing engine gracefully terminated by user.")
    except Exception as e:
        print(f"\n[ERROR] Could not start sniffing: {e}")

if __name__ == "__main__":
    main()
