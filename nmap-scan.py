# Nmap Scanner Python Code 
# Root privileges are needed to run nmap on any OS. (You can use sudo command)

# Import nmap Python Library
# port scanner
import nmap

scanner = nmap.PortScanner()

print("<----------------------------------------------------->")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan \n""")

print("You have selected option: ", resp)

resp_dict = {'1': ['-v -sS', 'tcp'], '2': ['-v -sU', 'udp'],
             '3': ['-v -sS -sV -sC -A -O', 'tcp']}
if resp not in resp_dict.keys():
    print("enter a valid option")
else:
    print("nmap version: ", scanner.nmap_version())

    # the # are port range to scan, the last part is the scan type
    scanner.scan(ip_addr, "1-1024", resp_dict[resp][0])
    print(scanner.scaninfo())

    if scanner.scaninfo() == 'up':
        print("Scanner Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        # display all open ports
        print("Open Ports: ", scanner[ip_addr][resp_dict[resp][1]].keys())

# nmap -sS <IP_address>
'''
SYN ACK Scan:

Nmap command: nmap -sS
Description: This command tells Nmap to perform a SYN scan, also known as a TCP SYN scan. It sends TCP SYN packets to the target ports and analyzes the responses to determine which ports are open, closed, or filtered. SYN scans are stealthy and fast because they don't complete the TCP handshake.
UDP Scan:

Nmap command: nmap -sU
Description: This command instructs Nmap to perform a UDP scan. It sends UDP packets to the target ports and analyzes the responses to identify open UDP ports. UDP scanning is essential for discovering services that may not respond to traditional TCP scans, such as DNS, DHCP, and SNMP.
Comprehensive Scan:

Nmap command: nmap -sS -sV -sC -A -O
Description: This command triggers a comprehensive scan that combines multiple scanning techniques:
-sS: SYN scan (TCP SYN scan) to identify open ports.
-sV: Service version detection to determine the versions of services running on open ports.
-sC: Script scanning using the default set of Nmap scripts (equivalent to -sC).
-A: Aggressive scanning, which enables OS detection, version detection, script scanning, and traceroute.
-O: OS detection to identify the underlying operating system of the target system.
This scan provides detailed information about the target system, including open ports, service versions, potential vulnerabilities, and the underlying operating system. However, it is more resource-intensive and time-consuming compared to individual scans.
'''