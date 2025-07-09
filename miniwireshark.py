# Advanced Packet Sniffer with Wireshark-like Features
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap
from threading import Thread
from datetime import datetime
import socket
import matplotlib.pyplot as plt
from collections import Counter

# Global State
sniffing = False
filter_option = "ALL"
captured_packets = []
filtered_packets = []
danger_ports = [21, 23, 445, 3389, 5800, 5900, 6667]

# GUI Setup
root = tk.Tk()
root.title("Advanced Packet Sniffer")
root.geometry("1000x800")

# Top Controls
top_frame = ttk.Frame(root)
top_frame.pack(pady=5)

def set_filter(value):
    global filter_option
    filter_option = value

filter_menu = ttk.Combobox(top_frame, values=["ALL", "TCP", "UDP", "ICMP", "DNS"], state="readonly")
filter_menu.set("ALL")
filter_menu.pack(side=tk.LEFT, padx=5)
filter_menu.bind("<<ComboboxSelected>>", lambda e: set_filter(filter_menu.get()))

ttks = lambda t, c: ttk.Button(top_frame, text=t, command=c).pack(side=tk.LEFT, padx=5)
ttks("Start Sniffing", lambda: start_sniffing())
ttks("Stop Sniffing", lambda: stop_sniffing())
ttks("Clear Output", lambda: clear_output())
ttks("Show Protocol Stats", lambda: show_protocol_stats())
ttks("Export to PCAP", lambda: export_pcap())
ttks("Show All", lambda: show_all_packets())

# Search Bar
search_frame = ttk.Frame(root)
search_frame.pack(pady=5)
ttk.Label(search_frame, text="Search by IP or Port:").pack(side=tk.LEFT)
search_entry = ttk.Entry(search_frame, width=30)
search_entry.pack(side=tk.LEFT, padx=5)
ttk.Button(search_frame, text="Search", command=lambda: search_packets()).pack(side=tk.LEFT)

# Packet Table
columns = ("Time", "Source", "Destination", "Protocol", "Length", "Info")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)
tree.pack(fill=tk.BOTH, expand=True)

# Detail View
bottom_frame = ttk.Frame(root)
bottom_frame.pack(fill=tk.BOTH, expand=True)

# Decoded Packet
detail_view = scrolledtext.ScrolledText(bottom_frame, height=10, font=("Courier", 10))
detail_view.pack(fill=tk.X)

# Hex Dump
hex_view = scrolledtext.ScrolledText(bottom_frame, height=10, font=("Courier", 10))
hex_view.pack(fill=tk.X)

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

def format_packet(pkt):
    if not IP in pkt:
        return None

    ip_layer = pkt[IP]
    proto = get_protocol(pkt)
    sport = dport = "-"
    flags = "-"
    ttl = ip_layer.ttl
    size = len(pkt)

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

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

    if dport != "-" and str(dport).isdigit() and int(dport) in danger_ports:
        info += f"  ⚠️ Suspicious Port Detected ({dport})!\n"

    return info

def process_packet(pkt):
    if not IP in pkt:
        return
    if filter_option != "ALL" and get_protocol(pkt) != filter_option:
        return

    captured_packets.append(pkt)
    filtered_packets.append(pkt)
    timestamp = datetime.now().strftime("%H:%M:%S")
    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = get_protocol(pkt)
    length = len(pkt)
    info = get_info(pkt)

    index = len(filtered_packets) - 1
    tree.insert("", tk.END, iid=str(index), values=(timestamp, src, dst, proto, length, info))

def on_packet_select(event):
    selected = tree.selection()
    if selected:
        index = int(selected[0])
        pkt = filtered_packets[index]
        detail_view.delete(1.0, tk.END)
        hex_view.delete(1.0, tk.END)
        detail_view.insert(tk.END, pkt.show(dump=True))
        try:
            hex_view.insert(tk.END, bytes(pkt).hex(" "))
        except:
            hex_view.insert(tk.END, "[!] Cannot render hex dump.")

def start_sniffing():
    global sniffing
    sniffing = True
    def sniffer():
        sniff(prn=process_packet, store=False, stop_filter=lambda x: not sniffing)
    Thread(target=sniffer, daemon=True).start()

def stop_sniffing():
    global sniffing
    sniffing = False

def clear_output():
    filtered_packets.clear()
    for item in tree.get_children():
        tree.delete(item)
    detail_view.delete(1.0, tk.END)
    hex_view.delete(1.0, tk.END)

def show_all_packets():
    for item in tree.get_children():
        tree.delete(item)
    detail_view.delete(1.0, tk.END)
    hex_view.delete(1.0, tk.END)
    filtered_packets.clear()
    for pkt in captured_packets:
        timestamp = datetime.now().strftime("%H:%M:%S")
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = get_protocol(pkt)
        length = len(pkt)
        info = get_info(pkt)
        filtered_packets.append(pkt)
        index = len(filtered_packets) - 1
        tree.insert("", tk.END, iid=str(index), values=(timestamp, src, dst, proto, length, info))

def search_packets():
    keyword = search_entry.get().strip()
    if not keyword:
        return
    for item in tree.get_children():
        tree.delete(item)
    detail_view.delete(1.0, tk.END)
    hex_view.delete(1.0, tk.END)
    filtered_packets.clear()
    for pkt in captured_packets:
        if IP in pkt:
            match = False
            if keyword in pkt[IP].src or keyword in pkt[IP].dst:
                match = True
            elif TCP in pkt and (keyword in str(pkt[TCP].sport) or keyword in str(pkt[TCP].dport)):
                match = True
            elif UDP in pkt and (keyword in str(pkt[UDP].sport) or keyword in str(pkt[UDP].dport)):
                match = True
            if match:
                timestamp = datetime.now().strftime("%H:%M:%S")
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = get_protocol(pkt)
                length = len(pkt)
                info = get_info(pkt)
                filtered_packets.append(pkt)
                index = len(filtered_packets) - 1
                tree.insert("", tk.END, iid=str(index), values=(timestamp, src, dst, proto, length, info))

def export_pcap():
    if not captured_packets:
        return
    filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
    if filename:
        wrpcap(filename, captured_packets)

def show_protocol_stats():
    protos = [get_protocol(pkt) for pkt in captured_packets]
    counts = Counter(protos)
    labels = list(counts.keys())
    sizes = list(counts.values())
    plt.figure(figsize=(6,6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title("Protocol Distribution")
    plt.show()

# Bind table click
tree.bind("<ButtonRelease-1>", on_packet_select)

root.mainloop()
