import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP
from threading import Thread
from datetime import datetime
import socket

# Global state
sniffing = False
filter_option = "ALL"
captured_packets = []  # Store for searching
danger_ports = [21, 23, 445, 3389, 5800, 5900, 6667]
log_file = "gui_packet_log.txt"

# Log function
def log_to_file(message):
    with open(log_file, "a") as f:
        f.write(message + "\n")

# Protocol filter logic
def packet_filter(packet):
    if filter_option == "TCP" and not packet.haslayer(TCP):
        return False
    if filter_option == "UDP" and not packet.haslayer(UDP):
        return False
    if filter_option == "ICMP" and not packet.haslayer(ICMP):
        return False
    return True

# DNS resolution (optional)
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

# Format detailed packet info
def format_packet(packet):
    ip_layer = packet[IP]
    proto = "Other"
    sport = dport = "-"
    flags = "-"
    ttl = ip_layer.ttl
    size = len(packet)

    if TCP in packet:
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
    elif UDP in packet:
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    elif ICMP in packet:
        proto = "ICMP"

    timestamp = datetime.now().strftime("%H:%M:%S")
    src_host = resolve_hostname(ip_layer.src)
    dst_host = resolve_hostname(ip_layer.dst)

    info = (
        f"[{timestamp}] {proto} Packet:\n"
        f"  From       : {ip_layer.src} ({src_host})\n"
        f"  To         : {ip_layer.dst} ({dst_host})\n"
        f"  TTL        : {ttl}\n"
        f"  Packet Size: {size} bytes\n"
        f"  Ports      : {sport} -> {dport}\n"
    )
    if proto == "TCP":
        info += f"  TCP Flags  : {flags}\n"

    if dport != "-" and int(dport) in danger_ports:
        info += f"  ⚠️ Suspicious Port Detected ({dport})!\n"

    return info

# Process and store each packet
def process_packet(packet):
    if not IP in packet:
        return
    captured_packets.append(packet)
    details = format_packet(packet)
    text_area.insert(tk.END, details + "\n" + "-"*60 + "\n")
    text_area.see(tk.END)
    log_to_file(details)

# Sniffer control
def start_sniffing():
    global sniffing
    sniffing = True
    text_area.insert(tk.END, "[*] Sniffing started...\n\n")
    def sniff_packets():
        sniff(prn=process_packet, store=False, stop_filter=lambda x: not sniffing, lfilter=packet_filter)
    Thread(target=sniff_packets, daemon=True).start()

def stop_sniffing():
    global sniffing
    sniffing = False
    text_area.insert(tk.END, "[!] Sniffing stopped.\n\n")

def set_filter(value):
    global filter_option
    filter_option = value

# Search logic
def search_packets():
    keyword = search_entry.get().strip()
    if not keyword:
        return
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, f"[*] Searching for '{keyword}' in captured packets...\n\n")
    for pkt in captured_packets:
        if IP in pkt:
            if keyword in pkt[IP].src or keyword in pkt[IP].dst:
                text_area.insert(tk.END, format_packet(pkt) + "\n" + "-"*60 + "\n")
            elif (TCP in pkt and (keyword in str(pkt[TCP].sport) or keyword in str(pkt[TCP].dport))) or \
                 (UDP in pkt and (keyword in str(pkt[UDP].sport) or keyword in str(pkt[UDP].dport))):
                text_area.insert(tk.END, format_packet(pkt) + "\n" + "-"*60 + "\n")

# GUI setup
root = tk.Tk()
root.title("Advanced Packet Sniffer")
root.geometry("950x600")

# Top controls
top_frame = ttk.Frame(root)
top_frame.pack(pady=5)

ttk.Label(top_frame, text="Filter Protocol:").pack(side=tk.LEFT, padx=5)
filter_menu = ttk.Combobox(top_frame, values=["ALL", "TCP", "UDP", "ICMP"], state="readonly")
filter_menu.current(0)
filter_menu.pack(side=tk.LEFT)
filter_menu.bind("<<ComboboxSelected>>", lambda e: set_filter(filter_menu.get()))

ttk.Button(top_frame, text="Start Sniffing", command=start_sniffing).pack(side=tk.LEFT, padx=10)
ttk.Button(top_frame, text="Stop Sniffing", command=stop_sniffing).pack(side=tk.LEFT)

# Search bar
search_frame = ttk.Frame(root)
search_frame.pack(pady=5)
ttk.Label(search_frame, text="Search IP / Port:").pack(side=tk.LEFT, padx=5)
search_entry = ttk.Entry(search_frame, width=30)
search_entry.pack(side=tk.LEFT)
ttk.Button(search_frame, text="Search", command=search_packets).pack(side=tk.LEFT, padx=5)

# Output box
text_area = scrolledtext.ScrolledText(root, height=30)
text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

root.mainloop()
