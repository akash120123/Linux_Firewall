Python Firewall (Using IPTables)

Description

Features

Block an IP Address – Adds an IP address to the IPTables block list.

Unblock an IP Address – Removes an IP address from the block list.

Show Blocked IPs – Displays currently blocked IP addresses.

Packet Sniffing – Monitors network traffic and displays packets from blocked or allowed sources.

Root Privilege Check – Ensures the script is run with root privileges.

Exception Handling – Handles errors gracefully, including invalid IP formats and keyboard interruptions.

Prerequisites

Before running the script, ensure you have the following:

A Linux operating system (as it uses IPTables)

Python 3.12.2 installed

Scapy library installed:

pip install scapy

(Optional)
Root privileges (Run the script with sudo)

Usage

Clone or download the script.

Open a terminal and navigate to the script's directory.

Run the script with:

sudo python3 firewall.py

Choose an option from the menu:

1: Block an IP address

2: Unblock an IP address

3: Show blocked IPs

4: Start packet sniffing

5: Exit

Example Usage

To block an IP address:

Enter the IP you want to block: 192.168.1.10
[+] 192.168.1.10 Is successfully added to blocked list...

To unblock an IP address:

Enter the IP you want to unblock: 192.168.1.10
[-] 192.168.1.10 successfully removed from the BLOCKED lists

Notes

This script modifies IPTables rules, so it requires root privileges.

It uses iptables -A INPUT -s <IP> -j DROP to block and iptables -D INPUT -s <IP> -j DROP to unblock IPs.

To see the IPTables rules manually, run:

sudo iptables -L

The packet sniffing feature uses Scapy, and it will capture packets from blocked and unblocked sources.

Troubleshooting

Error: "Permission denied"

Make sure to run the script with sudo.

Error: "ModuleNotFoundError: No module named 'scapy'"

Install Scapy using pip install scapy.

Blocked IPs do not persist after reboot

IPTables rules reset after a reboot. To make them persistent, consider using:

sudo iptables-save > /etc/iptables.rules



