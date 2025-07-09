# Network-Sniffer---MiniWireshark
# 🐍 Advanced Packet Sniffer (Wireshark-like)

A Python-based GUI packet sniffer built with **Scapy** and **Tkinter**, offering a real-time, user-friendly interface to inspect, filter, and analyze network traffic — inspired by Wireshark.

---

## 🚀 Features

- ✅ Live packet capture and display
- ✅ Filter by protocol (TCP, UDP, ICMP, DNS)
- ✅ Search by IP address or port number
- ✅ View detailed packet structure
- ✅ Hex and ASCII dump of packet data
- ✅ Protocol distribution statistics chart
- ✅ Export captured packets to `.pcap` file
- ✅ Clear and reload packet table without losing data
- ✅ "Show All" button to reset view after searching

---

## 🧰 Requirements

- Python 3.6 or higher
- [Scapy](https://scapy.net/)
- [Matplotlib](https://matplotlib.org/)

Install dependencies with:

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install scapy matplotlib
```

 How to Run:

```bash
sudo python miniwireshark.py

```

Note: Root privileges are required to capture network packets.

## Output:


![Screenshot From 2025-07-09 13-24-54](https://github.com/user-attachments/assets/37fb67df-4353-4bf4-a027-bbcca4f6f43b)


![Screenshot From 2025-07-09 13-55-46](https://github.com/user-attachments/assets/29ee53a4-edd9-4a5d-9b97-282273d2f146)



![Screenshot From 2025-07-09 13-56-37](https://github.com/user-attachments/assets/8d9dbfd9-9598-47b3-b8af-3b82b66aaf54)


![Screenshot From 2025-07-09 13-57-32](https://github.com/user-attachments/assets/2ea7af7f-4911-4818-954f-a8abd293e0d6)



![Screenshot From 2025-07-09 13-58-10](https://github.com/user-attachments/assets/d455c485-fdb3-4b87-8da0-257fa6538295)



## 🛡️ Disclaimer

This tool is intended for educational and ethical testing purposes only. Do not use it on networks you do not own or have permission to analyze.

## 🙌 Acknowledgements

    Scapy – Powerful Python packet manipulation library

    Tkinter – Built-in Python GUI framework

    Wireshark – The inspiration for this project
