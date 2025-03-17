import re
from scapy.all import sniff, IP
import os
import sys


# global list to store blocked ip
BLOCKED_IPS = []

# Function to clear screen
def clear_screen():
    # clear screen
    os.system("cls" if os.name == "nt" else "clear")


# To display banner
def display_banner():
    banner = r"""
    ========================================================
    =                                                      =
    =                 PYTHON FIREWALL                      =
    =                 (using IPTABLES)                     =
    =                                                      =
    ========================================================
    """
    print(banner)


# This function is Optional
def check_root():
    "Check if the script run as root"
    if os.getuid() != 0:
        print("This script requires root privileges. Please run as root")
        sys.exit(1)


# This function checks whether the provided ip is in correct format or not
def is_valid_ipv4(ip):
    # IPV4 regex for validation
    pattern = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    return re.match(pattern, ip) is not None


def block_ip(ip_addr):

    # This function block the ip ,
    try:
        os.system(
            f"sudo iptables -A INPUT -s {ip_addr} -j DROP"
        )  # BLOCK the ip address

        if ip_addr not in BLOCKED_IPS:
            BLOCKED_IPS.append(ip_addr)

        else:
            print(f"[+] IP {ip_addr} is already BLOCKED")
    except Exception as e:
        print(f"\n[!] Error occured while listing the blocked IPs : {e}")


# This function unblock the ip address that are added to BLOCKED_IPS lists
def unblock_ip(ip_addr):
    try:

        if not is_valid_ipv4(ip_addr):
            print(f"\n[!] {ip_addr} is not a valid IP")
        # Checking whether the ip is in blocked list or not
        if ip_addr in BLOCKED_IPS:
            # using iptables to UNBLOCK the ip
            os.system(f"sudo iptables -D INPUT -s {ip_addr} -j DROP")
            BLOCKED_IPS.remove(ip_addr)  # Removing from the blocked list
            print(f"\n[-] {ip_addr} succesfully removed from the BLOCKED lists")
        else:
            print(f"\n[!] {ip_addr} if not on BLOCKED lists")
    except ValueError as v:
        print(f"\n[!] Error occured : {v}")
    except Exception as e:
        print(f"\n[!] Unexpected error occured while unblocking the ip...{e}")


# This function list out the IP that are currently blocked
def show_rules():
    try:
        # Liist the blocked IPs
        if BLOCKED_IPS:
            print("\nBlocked IPs")
            for ip in BLOCKED_IPS:

                print(f"- {ip}\n")
        else:
            print(f"\n[*] No IPs are blocked currently")
    except Exception as e:
        print(f"\n[!] Error occured while blocking ip for you : {e}")


def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            if ip_src in BLOCKED_IPS:
                print(f"\n[!] Blocked packet from : {ip_src}")
                return
            else:
                print(f"\n[+] Allowed packet from: {ip_src}")
    except Exception as e:
        print(f"\n[!] Error occured : {e}")


# This function help in sniffing
def start__sniffing():
    try:
        print("\n[*] Starting sniffing packet.............")
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        print(f"\n[!] Error occured while sniffing the packets:{e}")


# This is the main Function
def main():
    clear_screen()
    display_banner()
    check_root()
    try:
        while True:
            print("\nSelect an option:\n ")
            print("1. Block an IP address")
            print("2. Unblock an IP address")
            print("3. Show currently blocked IPs")
            print("4. Start packet sniffing")
            print("5. Exit\n")

            choice = input("\nWhat would you like me to do for you 0_0[1-4]: ")
            if choice == "1":
                ip_to_block = input("\nEnter the IP you want to block: ")
                # need to validate ip
                if is_valid_ipv4(ip_to_block):
                    block_ip(ip_to_block)
                    print(
                        f"\n[+] {ip_to_block} Is successfully added to blocked list...\n"
                    )
                else:
                    print(f"\nPlease use correct IPv4 format......")

            elif choice == "2":
                ip_to_unblock = input("\n Enter the IP you want to unblock: ")
                # if ip_to_unblock != '':
                unblock_ip(ip_to_unblock)

            elif choice == "3":
                show_rules()

            elif choice == "4":
                start__sniffing()
            elif choice == "5":
                print("\n[!] Exiting the firewall program.........")
                break
            else:
                print("\n[!] Invalid input")
    # Handling keyboard interruption
    except KeyboardInterrupt:
        print("\n[!] Program interrupted by the user. Exiting safely........")
    except Exception as e:
        print("\n[!] Unexpected  error occured in main program : {e}")


if __name__ == "__main__":
    main()
