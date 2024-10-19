#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

inc_count = 0

def packetcallback(packet):
  try:
    global inc_count

    if packet.haslayer(TCP):
      if packet[TCP].flags == 0:
        inc_count += 1
        alerter("NULL Scan is detected from", packet[IP].src, "(TCP)", "")
      
      if packet[TCP].flags == 0x01:
        inc_count += 1
        alerter("FIN Scan is detected from", packet[IP].src, "(TCP)", "")

      if packet[TCP].flags == 0x29:
        inc_count += 1
        alerter("Xmas Scan is detected from", packet[IP].src, "(TCP)", "")

      if packet[TCP].dport == 445:
        inc_count += 1
        alerter("SMB Scan is detected from", packet[IP].src, "(TCP)", "")

      if packet[TCP].dport == 3389:
        inc_count += 1
        alerter("RDP Scan is detected from", packet[IP].src, "(TCP)", "")

      if packet[TCP].dport == 5900:
        inc_count += 1
        alerter("VNC Scan is detected from", packet[IP].src, "(TCP)", "")


    if packet.haslayer(Raw):
      payload = packet[Raw].load.decode(errors='ignore')
      if "USER " and "PASS " in payload:
        u_start = payload.find("USER ") + 5
        u_end = payload.find("\r\n", u_start)
        username = payload[u_start:u_end].strip()

        p_start = payload.find("PASS ") + 5
        p_end = payload.find("\r\n", p_start)
        password = payload[p_start:p_end].strip()

        inc_count += 1

        alerter("Usernames and passwords sent in-the-clear", packet[IP].src, "(FTP) ", f"(username:{username}, password:{password})")

      elif "LOGIN " in payload:
        c_start = payload.find("LOGIN ") + 6
        c_end = payload.find("\r\n", c_start)
        credentials = payload[c_start:c_end].strip()

        inc_count += 1

        alerter("Usernames sent in-the-clear", packet[IP].src, "(IMAP) ", f"(username:{credentials})")

      elif "Authorization: Basic" in payload:
        credentials = payload.split("Authorization: Basic")[1].strip().split('\n')[0]
        inc_count += 1


        decoded = base64.b64decode(credentials.encode('utf-8'))
        plain = decoded.decode('utf-8')
        sep = plain.split(":")

        alerter("Usernames sent in-the-clear", packet[IP].src, "(HTTP) ", f"(username:{sep[0]}, password:{sep[1]})")

      elif "Nikto" in payload:
        inc_count += 1
        alerter("Nikto Scan is detected from", packet[IP].src, "(HTTP)", "")

      
    
  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    print(e)
    #pass

def alerter(incident, IP, service, data):
  print(f"ALERT #{inc_count}: {incident} {IP} {service}{data}!")


# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")