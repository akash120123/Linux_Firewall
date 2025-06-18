# Python Firewall (Using IPTables)

## 📄 Description

A simple Python-based firewall using `IPTables`, designed for Linux systems. It allows users to block/unblock IP addresses and monitor network packets.

---

## ✨ Features

- **Block an IP Address** – Adds an IP address to the IPTables block list.  
- **Unblock an IP Address** – Removes an IP address from the block list.  
- **Show Blocked IPs** – Displays currently blocked IP addresses.  
- **Packet Sniffing** – Monitors network traffic and displays packets from blocked or allowed sources.  
- **Root Privilege Check** – Ensures the script is run with root privileges.  
- **Exception Handling** – Handles errors gracefully, including invalid IP formats and keyboard interruptions.

---

## ⚙️ Prerequisites

Before running the script, ensure you have the following:

- A **Linux** operating system (as it uses `IPTables`)
- **Python 3.12.2** installed
- **Scapy** library installed:

```bash
pip install scapy
