# Network Scanner and Vulnerability Detector

![Screenshot 2025-01-16 190048](https://github.com/user-attachments/assets/3c6f7840-334c-417d-a26f-0a114b19957c)



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
```
## Installation

1. Clone the repository to your local machine using the following command:
   ```
   git clone git@github.com:nefariousjosiah/Network-Scanner-GUI-CVSS-.git
   ```
2. Navigate into the project directory
3. Install the required dependencies
   ```
   pip install -r requirements.txt
   ```
4. Run the Script.py using python

## Usage

1. **Scan a Custom Network**:
   - Enter a network range in the format `192.168.x.x/24` (e.g., `192.168.1.0/24`) in the provided input field.
   - Click the "Scan" button to start scanning.

2. **Auto Scan Local Network**:
   - If you prefer, you can click the "Scan Local Network" button to automatically scan your local network.

3. **Scan Results**:
   - The results will display the IP and MAC addresses of the devices found on the network.
   - Open ports and any potential vulnerabilities will also be shown.
   - Once the scan completes, a security rating (1-10) for the network is provided.

## Example Output

After completing the scan, the tool will display:

```

Scanning the network: 192.168.1.0/24...

Devices found on the network: IP: 192.168.1.10, MAC: 00:1A:2B:3C:4D:5E IP: 192.168.1.11, MAC: 00:1A:2B:3C:4D:5F

Scanning open ports on 192.168.1.10... Open ports on 192.168.1.10: [22, 80]

Potential vulnerability: SSH port 22 is open! Potential vulnerability: HTTP port is open. Ensure the server is secured.

Security Rating: 7/10
```
   
