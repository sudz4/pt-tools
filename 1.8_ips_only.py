"""get IPs only"""

#libs
import nmap
import ipaddress
import socket

def normalize_ip_address(ip):
    try:
        return str(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        try:
            return str(ipaddress.IPv6Address(ip))
        except ipaddress.AddressValueError:
            return None

def resolve_hostname_to_ip(hostname):
    try:
        return socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
    except socket.gaierror:
        return None

def get_ip_addresses(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments="-sn")
    ip_addresses = []

    for host in nm.all_hosts():
        normalized_ip = normalize_ip_address(host)
        if normalized_ip:
            ip_addresses.append(normalized_ip)
        else:
            resolved_ips = resolve_hostname_to_ip(host)
            if resolved_ips:
                for res in resolved_ips:
                    family, _, _, _, addr = res
                    if family == socket.AF_INET or family == socket.AF_INET6:
                        ip_addresses.append(addr[0])

    return ip_addresses

if __name__ == "__main__":
    ip_ranges = ["192.168.1.0/24", "10.211.55.0/24"]
    
    for ip_range in ip_ranges:
        ip_addresses = get_ip_addresses(ip_range)
        for ip in ip_addresses:
            print(ip)
