import socket
import subprocess
import sys
from datetime import datetime
import threading
import ipaddress
import csv
from collections import defaultdict

results = defaultdict(list)

def scan_port(ip_address, port):
    global results
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((str(ip_address), port))
    if result == 0:
        print("Port {}: Open on {}".format(port, str(ip_address)))
        results[ip_address].append(port)
    sock.close()

subprocess.call('cls', shell=True)

remoteHost = input("Enter a remote host or network to scan (e.g. 192.168.0.1, 192.168.0.1-10, 192.168.0.0/24): ")
ports = input("Enter the port(s) to scan (e.g. 22, 80-100): ")

ip_list = []
try:
    network = ipaddress.ip_network(remoteHost)
    ip_list = [str(ip) for ip in network.hosts()]
except ValueError:
    try:
        if "-" in remoteHost:
            start_ip, end_ip = remoteHost.split("-")
            ip_range = ipaddress.ip_range(start_ip, end_ip)
            ip_list = [str(ip) for ip in ip_range]
        else:
            ipaddress.ip_address(remoteHost)
            ip_list = [remoteHost]
    except ValueError:
        print("Invalid input. Please enter an IP address, IP range (e.g. 192.168.0.1-10), or CIDR notation (e.g. 192.168.0.0/24).")
        sys.exit()

port_list = []
if ports:
    for port_range in ports.split(","):
        if "-" in port_range:
            start_port, end_port = port_range.split("-")
            port_list.extend(range(int(start_port), int(end_port)+1))
        else:
            port_list.append(int(port_range))
else:
    port_list = range(1, 1025)

t1 = datetime.now()

try:
    threads = []
    for ip in ip_list:
        for port in port_list:
            thread = threading.Thread(target=scan_port, args=(ip, port))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

except KeyboardInterrupt:
    print("You pressed Ctrl+C")
    sys.exit()
except socket.gaierror:
    print('Hostname could not be resolved. Exiting')
    sys.exit()
except socket.error:
    print("Couldn't connect to server")
    sys.exit()

t2 = datetime.now()
total = t2 - t1
print('Scanning Completed in:', total)

csv_filename = f"{remoteHost.replace('/', '_')}_portscan_results.csv"

with open(csv_filename, 'w', newline='') as csvfile:
    fieldnames = ['IP Address', 'Open Ports']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for ip, ports in results.items():
        writer.writerow({'IP Address': ip, 'Open Ports': ' '.join(map(str, ports))})

print(f"Results saved to {csv_filename}")
