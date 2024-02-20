# Network Mapping Nmap Python Code.  

import nmap

# Prompt user for subnet to scan
subnet = input("Enter subnet to scan: ")

# Create a new nmap scanner object
nm = nmap.PortScanner()

# Perform network mapping scan on the specified subnet
nm.scan(hosts=subnet, arguments='-sn')

# Print out the list of hosts that were found
for host in nm.all_hosts():
    print('Host found: %s (%s)' % (host, nm[host].hostname()))

'''
Performing Network Mapping Scan: The scan() method of the PortScanner object is
 called with the specified subnet and the argument -sn, indicating that a ping scan should be performed to discover
   live hosts on the subnet.

Printing Hosts Found: After the scan is completed, the code iterates over the list of hosts found (nm.all_hosts()) 
and prints out each host's IP address and hostname (if available).
'''