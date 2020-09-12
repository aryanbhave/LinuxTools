#!/usr/bin/env python

import scapy.all as scapy
import argparse


def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Pick an interface to sniff packets on.")
    (options) = parser.parse_args()
    return options


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffPacket)


def sniffPacket(packet):
    print(packet)


options = getArguments()
interface = options.interface
sniffer(interface)
