# WiFi Controller

A simple local network management tool for Windows. It scans devices on the network, lets you assign names, and can temporarily cut and restore internet access for a selected device. The UI is built with customtkinter.

## Features

- Scan local network devices (IP/MAC/device name)
- Assign device-specific names and persist them
- Temporarily block/restore internet access for a selected device
- Live traffic log (shows packets from the target device)
- OS detection with Nmap

## Requirements

- Windows 10/11
- Python 3.10+ (recommended)
- Npcap (required for Scapy)
- Nmap (required for OS detection)

## Installation

1) Create a virtual environment:

```bash
python -m venv .venv
```

2) Activate the environment:

PowerShell:

```bash
.venv\Scripts\Activate.ps1
```

CMD:

```bash
.venv\Scripts\activate
```

3) Install dependencies:

```bash
pip install -r requirements.txt
```

4) Install Npcap and Nmap:

- Npcap: https://npcap.com/
- Nmap: https://nmap.org/download.html

## Run

```bash
python main.py
```

## Configuration

Update the network scan range and gateway (modem) IPs to match your own network. You must enter your modem IP and your network range in these lines.

- Scan range: `scan_network("192.***.*.*/**")` in [gui_app.py](gui_app.py#L40)
- Gateway IP: `gateway_ip = "192.***.*.*"` in [gui_app.py](gui_app.py#L77)

## Files

- [main.py](main.py) Application entry point
- [gui_app.py](gui_app.py) UI and user actions
- [network_manager.py](network_manager.py) Network scanning and ARP spoofing logic
- [known_devices.json](known_devices.json) Device name database
- [requirements.txt](requirements.txt) Python dependencies

## Security and Disclaimer

This project should only be used on your own network, on authorized devices, for testing purposes. Unauthorized use may result in legal consequences.
