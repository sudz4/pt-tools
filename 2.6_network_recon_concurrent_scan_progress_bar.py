import nmap
import concurrent.futures
from tqdm import tqdm
import itertools
import ipaddress
import threading  # #IMPORTANT = performance -> import the threading module

def ip_range_count(ip_ranges):
    total_ips = 0
    for ip_range in ip_ranges:
        total_ips += sum(1 for _ in ipaddress.ip_network(ip_range).hosts())
    return total_ips

def scan_networks(ip_ranges):
    def scan_ip(ip, progress_bar):
        scanner = nmap.PortScanner()
        result = scanner.scan(str(ip), arguments='-sV -O')
        devices = []

        for ip, info in result['scan'].items():
            if info['status']['state'] == 'up':
                hostname = info['hostnames'][0]['name'] if len(info['hostnames']) > 0 else "Unknown"
                mac_address = info['addresses']['mac'] if 'mac' in info['addresses'] else "Unknown"
                os = info['osmatch'][0]['name'] if len(info['osmatch']) > 0 else "Unknown"
                vendor = info['vendor'][mac_address] if mac_address in info['vendor'] else "Unknown"
                # count the number of available data points
                data_points = sum([hostname != "Unknown", mac_address != "Unknown", os != "Unknown", vendor != "Unknown"])

                if data_points >= 2:
                    devices.append((ip, hostname, mac_address, os, vendor))

        with progress_bar_lock:
            progress_bar.update(1)

        return devices

    with concurrent.futures.ThreadPoolExecutor() as executor:
        total_ips = ip_range_count(ip_ranges)
        progress_bar = tqdm(total=total_ips, desc="Scanning IP Addresses", ncols=100)
        progress_bar_lock = threading.Lock()  # Use threading.Lock() instead of concurrent.futures.Lock()

        # Flatten the list of IP addresses
        all_ips = list(itertools.chain.from_iterable(ipaddress.ip_network(ip_range).hosts() for ip_range in ip_ranges))

        # Scan IPs concurrently
        results = list(executor.map(lambda ip: scan_ip(ip, progress_bar), all_ips))

        progress_bar.close()

    for devices in results:
        for ip, hostname, mac_address, os, vendor in devices:
            print(f"Device found: {ip} ({hostname}), MAC Address: {mac_address}, OS: {os}, Vendor: {vendor}")

if __name__ == "__main__":
    # set IP ranges to scan
    ip_ranges = ['192.168.1.0/24', # local host machine(s) private IP addr-> 192. is common within local networks
                '10.211.55.0/24'] # parallels VMs private IP addr-> 10. is usually for VMs
                #'172.16.0.0/24', # another private IP address range you should maybe scan for thoroughness
                #'169.254.0.0/24'] # special IP addr range used for link-local addressing.
                # 169. IPs for link-local addressing-> devices on a network can automatically 
                # assign themselves IP addresses within this range if no other IP address is available. 

     # call the scan_networks function
    scan_networks(ip_ranges)

"""
Technical Notes

nmap -> root privileges workaround
If you are running your Python program in a virtual environment and need to run nmap with 
root privileges, you can use sudo to run the nmap command as root, while still using the 
virtual environment for your Python program.

To do this, activate your virtual environment, and then use the -E flag with sudo to 
preserve the environment variables from the virtual environment. 
For example, if your virtual environment is located at /home/user/myenv, you can activate 
it and then run nmap with root privileges using the following commands:

                    source /home/user/myenv/bin/activate
                    sudo -E python myprogram.py

This will activate your virtual environment and then run your Python program with root privileges, 
while still preserving the environment variables from the virtual environment.
"""