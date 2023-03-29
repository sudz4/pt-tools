# get IPs ONLY
# this is good for quickly seeing IPs maybe with the hostname. those are probably real on the network or had been on the network

import nmap

def get_ip_addresses(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments="-sn")
    ip_addresses = []

    for host in nm.all_hosts():
        ip_addresses.append(host)

    return ip_addresses

if __name__ == "__main__":
    ip_ranges = ["192.168.1.0/24", "10.211.55.0/24"]
    
    for ip_range in ip_ranges:
        ip_addresses = get_ip_addresses(ip_range)
        for ip in ip_addresses:
            print(ip)
