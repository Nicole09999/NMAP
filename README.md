# NMAP
Nmap is a network exploration tool and security scanner that is used to discover hosts and services on a computer network and to security audit the network. functionalities explored are  Host Discovery , Port Scanning , Version Detection , OS Detection , Network Mapping.


## Prerequisites

- Python 3.x installed on your system
- `nmap` Python library installed (`pip install python-nmap`)

## Usage

1. Clone or download the Python script (`network_mapping.py`) to your local machine.

2. Open a terminal or command prompt.

3. Navigate to the directory containing the Python script.

4. Run the Python script:

   ```bash
   python network_mapping.py

When prompted, enter the subnet you want to scan (e.g., 192.168.0.0/24).

The script will perform a network mapping scan using Nmap and display the discovered hosts along with their IP addresses and hostnames (if available).

Example



Enter subnet to scan: 192.168.0.0/24

Host found: 192.168.0.1 (router.example.com)
Host found: 192.168.0.2 (desktop.example.com)
Host found: 192.168.0.3 (laptop.example.com)
...

   
