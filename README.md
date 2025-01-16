# Network Scanner and Vulnerability Detector

This project is a network scanning and vulnerability detection tool built using Python, utilizing `scapy` for network scanning and `socket` for open port checking. It features a graphical user interface (GUI) made with `CustomTkinter` for ease of use. The tool can scan a specified network for devices, check for open ports, and provide basic vulnerability assessments based on common open ports.

## Features

- **Network Scanning**: Scan your network for connected devices (e.g., IP and MAC addresses).
- **Port Scanning**: Scan devices for common open ports (e.g., HTTP, HTTPS, SSH).
- **Vulnerability Detection**: Basic checks for common vulnerabilities like open ports.
- **GUI Interface**: Easy-to-use graphical interface built with `CustomTkinter`.
- **Network Rating**: Provides a security rating (1-10) for the scanned network based on open ports and vulnerabilities.

## Requirements

To run the script, you'll need the following Python libraries:

- `scapy`: For network packet manipulation and scanning.
- `customtkinter`: For building the GUI.

You can install all the required libraries by running the following command:

```bash
pip install -r requirements.txt
