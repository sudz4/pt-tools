import subprocess
import re

def get_ip_info():
    # Run the 'ip route' command and store the output in 'output'
    output = subprocess.check_output("ip route", shell=True, text=True)

    # Regular expressions to search for router's IP address and local IP address
    router_ip_regex = r"default via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    local_ip_regex = r"src (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    # Search for router's IP address and local IP address in the 'output'
    router_ip = re.search(router_ip_regex, output)
    local_ip = re.search(local_ip_regex, output)

    # Extract the IP addresses from the regex search results
    router_ip = router_ip.group(1) if router_ip else None
    local_ip = local_ip.group(1) if local_ip else None

    return local_ip, router_ip

if __name__ == "__main__":
    local_ip, router_ip = get_ip_info()

    if local_ip and router_ip:
        print(f"Machine's IP address: {local_ip}")
        print(f"Router's IP address: {router_ip}")
    else:
        print("Failed to retrieve IP addresses. Please check your network connection.")
