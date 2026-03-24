
# huuhuu-scanner
802.11 WiFi reconnaissance tool using Scapy for real-time packet analysis and network discovery
=======
# huuhuu scanner

A lightweight WiFi reconnaissance tool built in Python using Scapy.

## Features

- Real-time WiFi network scanning  
- Signal strength analysis (RSSI and classification)  
- Security detection (Open, WPA, WPA2, WPA3)  
- Live statistics (networks, clients, strongest access point)  
- Focus mode (track a specific BSSID)  
- Passive client detection  
- Channel hopping  
- Identification of weak or open networks  

## Installation

Clone the repository:

```bash
git clone https://github.com/paablorsc/huuhuu-scanner.git
cd huuhuu-scanner
pip install -r requirements.txt


## Requirements

- Linux (Kali recommended)  
- Python 3  
- Scapy  
- Wireless adapter supporting monitor mode  

## Usage

```bash
sudo python3 huuhuu_scanner.py

## Example Output

SSID BSSID CH BAND RSSI SIG SEC CLIENTS
MyWiFi AA:BB:CC:DD:EE:FF 6 2.4G -45 Strong Secure 3
Guest 11:22:33:44:55:66 1 2.4G -70 Weak Open 1

## How it Works

The scanner uses Scapy to capture 802.11 beacon frames while the wireless interface is in monitor mode.

- Extracts SSID, BSSID, channel, and encryption information  
- Measures signal strength (RSSI) from captured packets  
- Classifies networks based on security type  
- Performs channel hopping to discover networks across frequencies  
- Passively detects client devices from observed traffic  

## Controls

- CTRL+A → Return to main menu  
- CTRL+C → Exit and restore WiFi  

## Limitations

- Requires a wireless adapter that supports monitor mode  
- Signal strength values depend on hardware and environment  
- Client detection is passive and may not capture all devices  
- Only tested on Linux-based systems  

## Disclaimer

This tool is intended for educational and research purposes only.

It is designed to be used in controlled environments such as:
- personal labs  
- authorized penetration testing environments  
- networks you own or have explicit permission to test  

Unauthorized use of this tool against networks without permission may be illegal.

The author is not responsible for any misuse.
