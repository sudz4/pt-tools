# libraries
import platform
import socket
import fcntl
import struct
import netifaces
import urllib.request
import psutil

# GET hostname and local IP address
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

# GET public IP address
public_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')

# GET public IPv6 addresses
ipv6_addresses = []
try:
    ipv6_addresses = socket.getaddrinfo(socket.getfqdn(), None, socket.AF_INET6)[0][4]
except:
    pass

# GET network interface information
ifaces = netifaces.interfaces()
for iface in ifaces:
    try:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ipv4 = addrs[netifaces.AF_INET][0]
            if ipv4['addr'] != '127.0.0.1':
                netmask = ipv4['netmask']
                broadcast = ipv4['broadcast']
                mac_addr = fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8927, struct.pack('256s', bytes(iface[:15], 'utf-8')))[18:24]
                mac_addr = ':'.join(['{:02x}'.format(x) for x in mac_addr])
                hostname_ip = ipv4['addr'] # GETs hostname IP addresss
                break
    except:
        pass

# GET operating system information
os_name = platform.system()
os_release = platform.release()
os_version = platform.version()

# GET CPU information
cpu_count = psutil.cpu_count(logical=False)
cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A'
cpu_temp = psutil.sensors_temperatures().get('coretemp')[0].current if 'coretemp' in psutil.sensors_temperatures() else 'N/A'

# GET memory information
mem_total = round(psutil.virtual_memory().total / (1024 ** 3), 2)
mem_used = round(psutil.virtual_memory().used / (1024 ** 3), 2)
mem_free = round(psutil.virtual_memory().free / (1024 ** 3), 2)

# print network, operating system, CPU, and memory information
print('Hostname: {}'.format(hostname))
print('Hostname IP Address (IPv4): {}'.format(hostname_ip)) # print hostname IP address
print('Local IP Address (IPv4): {}'.format(local_ip))
print('Public IP Address (IPv4): {}'.format(public_ip))
for addr in ipv6_addresses:
    if '%' not in addr:
        print('IP Address (IPv6): {}'.format(addr))
print('Netmask: {}'.format(netmask))
print('Broadcast: {}'.format(broadcast))
print('MAC Address: {}'.format(mac_addr))
print('Operating System: {}'.format(os_name))
print('Kali Linux Version: {}'.format(os_release))
print('Kernel Version: {}'.format(os_version))
print('CPU Count: {}'.format(cpu_count))
print('CPU Frequency (MHz): {}'.format(cpu_freq))
print('CPU Temperature (°C): {}'.format(cpu_temp))
print('Memory Total (GB): {}'.format(mem_total))
print('Memory Used (GB): {}'.format(mem_used))
print('Memory Free (GB): {}'.format(mem_free))


####---->END OF PROGRAM<----####


"""
***SSL vs TSL***
SSL (Secure Sockets Layer) and TLS (Transport Layer Security) are cryptographic protocols that are used -
- to secure communication over the internet. They are used to encrypt data as it is transmitted between a client and a server, 
in order to prevent unauthorized access, interception or tampering of the data.

TLS is the newer and more secure version of SSL

Both SSL and TLS work by using a combination of symmetric and asymmetric cryptography.
SSL/TLS is used to secure a wide range of internet communication, including web browsing, 
email, instant messaging, and other applications.

"""