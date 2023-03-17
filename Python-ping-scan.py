import socket
import subprocess
import sys
from datetime import datetime
import threading
import ipaddress
from ping3 import ping
import csv
import concurrent.futures

# Remember to install the ping3 package before running this script:
# pip install ping3

# Define a function that will ping a single IP address
def ping_ip(ip_address):
    response_time = ping(ip_address, timeout=2)
    if response_time is not None:
        print(f"{ip_address} is alive. Response time: {response_time} ms")
        return (ip_address, response_time)
    return None

def save_results_to_csv(filename, results):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Response Time (ms)']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for result in results:
            writer.writerow({'IP Address': result[0], 'Response Time (ms)': result[1]})

subprocess.call('cls', shell=True)

# Ask for input
remoteHost = input("Enter a remote host or network to scan (e.g. 192.168.0.1, 192.168.0.1-10, 192.168.0.0/24): ")

# Convert the input to a list of IP addresses to scan
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

# Check what time the scan started
t1 = datetime.now()

# Using multiple threads to ping each IP address in the list
try:
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(filter(None, executor.map(ping_ip, ip_list)))

except KeyboardInterrupt:
    print("You pressed Ctrl+C")
    sys.exit()
except socket.gaierror:
    print('Hostname could not be resolved. Exiting')
    sys.exit()
except socket.error:
    print("Couldn't connect to server")
    sys.exit()

# Checking the time again
t2 = datetime.now()
# Calculates the difference of time, to see how long it took to run the script
total = t2 - t1
# Printing the information to screen
print('Scanning Completed in:', total)

# Save the results to a CSV file
csv_filename = f"{remoteHost.replace('/', '_')}_scan_results.csv"
save_results_to_csv(csv_filename, results)
print(f"Results saved to {csv_filename}")

