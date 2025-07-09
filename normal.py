# Advanced Packet Sniffer with Wireshark-like Features
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap
from threading import Thread
from datetime import datetime
import socket
import matplotlib.pyplot as plt
from collections import Counter
import tempfile

# Global State
sniffing = False
filter_option = "ALL"
captured_packets = []
packet_summary = []
danger_ports = [21, 23, 445, 3389, 5800, 5900, 6667]

# GUI Setup
root = tk.Tk()
root.title("Advanced Packet Sniffer")
root.geometry("1000x700")

# Packet Table
columns = ("Time", "Source", "Destination", "Protocol", "Length", "Info")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)
tree.pack(fill=tk.BOTH, expand=True)

# Bottom Detail View
detail_view = scrolledtext.ScrolledText(root, height=10, font=("Courier", 10))
detail_view.pack(fill=tk.X)

# Display packet details when row is clicked
def on_packet_select(event):
    selected = tree.selection()
    if selected:
        index = int(selected[0])
        pkt = captured_packets[index]
        detail_view.delete(1.0, tk.END)
        detail_view.insert(tk.END, pkt.show(dump=True))
tree.bind("<ButtonRelease-1>", on_packet_select)

# Utility Functions
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_protocol(pkt):
    if pkt.haslayer(TCP): return "TCP"
    if pkt.haslayer(UDP): return "UDP"
    if pkt.haslayer(ICMP): return "ICMP"
    if pkt.haslayer(DNS): return "DNS"
    return "Other"

def get_info(pkt):
    if pkt.haslayer(DNS):
        if pkt.haslayer(DNSQR):
            return f"DNS Query: {pkt[DNSQR].qname.decode()}"
        if pkt.haslayer(DNSRR):
            return f"DNS Response"
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load
        if b"HTTP" in payload:
            return payload[:60].decode(errors="ignore")
    return get_protocol(pkt)

def process_packet(pkt):
    if not IP in pkt:
        return
    timestamp = datetime.now().strftime("%H:%M:%S")
    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = get_protocol(pkt)
    length = len(pkt)
    info = get_info(pkt)
    
    # Add to table and storage
    index = len(captured_packets)
    tree.insert("", tk.END, iid=str(index), values=(timestamp, src, dst, proto, length, info))
    captured_packets.append(pkt)

# Sniffer

def start_sniffing():
    global sniffing
    sniffing = True
    def sniffer():
        sniff(prn=process_packet, store=False, stop_filter=lambda x: not sniffing)
    Thread(target=sniffer, daemon=True).start()

def stop_sniffing():
    global sniffing
    sniffing = False

def export_pcap():
    if not captured_packets:
        return
    filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
    if filename:
        wrpcap(filename, captured_packets)

# Protocol Chart

def show_protocol_stats():
    protos = [get_protocol(pkt) for pkt in captured_packets]
    counts = Counter(protos)
    labels = list(counts.keys())
    sizes = list(counts.values())
    plt.figure(figsize=(6,6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title("Protocol Distribution")
    plt.show()

# Controls
frame = ttk.Frame(root)
frame.pack(pady=5)

ttks = lambda t, c: ttk.Button(frame, text=t, command=c).pack(side=tk.LEFT, padx=5)
ttks("Start Sniffing", start_sniffing)
ttks("Stop Sniffing", stop_sniffing)
ttks("Show Protocol Stats", show_protocol_stats)
ttks("Export to PCAP", export_pcap)

root.mainloop()
