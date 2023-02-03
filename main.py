#!/usr/bin/python

import nmap

scanner = nmap.PortScanner()

print("Simple nmap scanner\n"
      "-------------------\n")

ipaddr = input("Enter IP address: ")
print(f"Scanning IP: {ipaddr}")

scantype = input("""SCAN TYPES AVAILABLE:
      1) SYN ACK
      2) UDP scan
      3) Comprehensive scan
Enter scan type: """)


if scantype == '1':
    print(f"Nmap version: {scanner.nmap_version()}")
    print("Scanning...")
    scanner.scan(ipaddr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print(f"Host status: {scanner[ipaddr].state()}")
    print(scanner[ipaddr].all_protocols())
    print(f"Open ports: {scanner[ipaddr]['tcp'].keys()}")
elif scantype == '2':
    print(f"Nmap version: {scanner.nmap_version()}")
    print("Scanning...")
    scanner.scan(ipaddr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print(f"Host status: {scanner[ipaddr].state()}")
    print(scanner[ipaddr].all_protocols())
    print(f"Open ports: {scanner[ipaddr]['udp'].keys()}")
elif scantype == '3':
    print(f"Nmap version: {scanner.nmap_version()}")
    print("Scanning...")
    scanner.scan(ipaddr, '1-65535', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print(f"Host status: {scanner[ipaddr].state()}")
    print(scanner[ipaddr].all_protocols())
    print(f"Open ports: {scanner[ipaddr]['tcp'].keys()}")
else:
      print(f"Invalid option: {scantype}. Exiting")
