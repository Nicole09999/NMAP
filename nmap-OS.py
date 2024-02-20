# OS Detection Nmap Python Code

import nmap

# Prompt user for IP address to scan
ip_address = input("Enter IP address to scan: ")

# Create a new nmap scanner object
nm = nmap.PortScanner()

# Perform OS detection scan on the specified IP address
nm.scan(hosts=ip_address, arguments='-O')

# Print out the OS information for the host
if ip_address in nm.all_hosts():
    if 'osmatch' in nm[ip_address]:
        os_match = nm[ip_address]['osmatch']
        for os in os_match:
            print('OS Name : %s\tAccuracy : %s' % (os['name'], os['accuracy']))
    else:
        print('OS information not found')
else:
    print('Host not found')

'''
Input IP Address: The user inputs an IP address to scan for OS detection.

Nmap Scan Initialization: An instance of the PortScanner class from the nmap library is created. This object is used to perform the scanning operations.

Performing OS Detection Scan: The scan() method of the PortScanner object is called with the specified IP address and the argument -O, indicating that an OS detection scan should be performed.

Analyzing Scan Results: The code checks if the specified IP address is found in the scan results. 
If the IP address is found, it checks if OS information is available (osmatch in the scan results). 
If OS information is found, it iterates over each detected OS and prints its name and accuracy.
 If no OS information is found, it prints a message indicating that OS information was not found.
 If the specified IP address is not found in the scan results, it prints a message indicating that the host was not found.
'''