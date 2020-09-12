#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="Input an IP or range of IP's to scan.")
    (options) = parser.parse_args()

    if not options.ip:
        parser.error("[-] Please specify an IP or range, use --help for more info.")
    else:
        return options


def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answered_list = scapy.srp(arp_req_broadcast, timeout=1)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def display(client_list):
    print("IP\t\t\tMAC")
    print("-" * 41)
    for client in client_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
ipAddr = str(options.ip)
clientList = scan(ipAddr)
display(clientList)
