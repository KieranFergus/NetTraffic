alarm.py: Network traffic detector. 
Detects and alerts the user of each instance of the following types of network traffic:
- NULL scan
- FIN scan
- Xmas scan
- Usernames and passwords sent in-the-clear via HTTP Basic Authentication, FTP, and IMAP
- Nikto scan
- Scans for Server Message Block (SMB) protocol
- Scans for Remote Desktop Protocol (RDP)
- Scans for Virtual Network Computing (VNC) instance(s)

Must have Scapy installed
How to run:  alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]
