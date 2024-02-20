# Version Detection Nmap Python Code

import nmap

# Prompt user for IP address to scan
ip_address = input("Enter IP address to scan: ")

# Create a new nmap scanner object
nm = nmap.PortScanner()

# Perform version detection scan on the specified IP address
nm.scan(hosts=ip_address, arguments='-sV')

# Print out the version information for the host
if ip_address in nm.all_hosts():
    for proto in nm[ip_address].all_protocols():
        print('Protocol : %s' % proto)
        ports = nm[ip_address][proto].keys()
        for port in ports:
            print('Port : %s\tState : %s\tName : %s\tProduct : %s\tVersion : %s' %
                  (port, nm[ip_address][proto][port]['state'], nm[ip_address][proto][port]['name'],
                   nm[ip_address][proto][port]['product'], nm[ip_address][proto][port]['version']))
else:
    print('Host not found')

# nmap -sV <IP_address>
