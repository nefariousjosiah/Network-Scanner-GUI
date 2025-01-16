import customtkinter as ctk
from scapy.all import ARP, Ether, srp
import socket
from threading import Thread
import webbrowser
import ipaddress

# Initialize CustomTkinter
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# Function to get local IP address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # Connect to an address (this does not actually open the connection)
        s.connect(('10.254.254.254', 1))
        local_ip = s.getsockname()[0]
    except:
        local_ip = '127.0.0.1'  # Fallback to localhost if no network
    finally:
        s.close()
    return local_ip

# Function to scan for devices on the local network
def scan_network(network, result_box):
    result_box.delete("0.0", "end")
    result_box.insert("0.0", f"Scanning the network: {network}...\n")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = srp(arp_request_broadcast, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    if devices:
        result_box.insert("end", "\nDevices found on the network:\n")
        for device in devices:
            result_box.insert("end", f"IP: {device['ip']}, MAC: {device['mac']}\n")
    else:
        result_box.insert("end", "\nNo devices found on the network.")
    
    return devices

# Function to scan open ports on a specific device
def scan_ports(ip, ports, result_box):
    result_box.insert("end", f"\nScanning open ports on {ip}...\n")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    if open_ports:
        result_box.insert("end", f"Open ports on {ip}: {open_ports}\n")
    else:
        result_box.insert("end", f"No open ports found on {ip}.\n")
    return open_ports

# Function to check vulnerabilities
def check_vulnerabilities(ip, result_box):
    result_box.insert("end", f"\nChecking vulnerabilities for {ip}...\n")
    open_ports = scan_ports(ip, ports=[21, 22, 23, 80, 8080], result_box=result_box)
    vulnerabilities = 0
    if 22 in open_ports:
        result_box.insert("end", "Potential vulnerability: SSH port 22 is open!\n")
        vulnerabilities += 1
    if 80 in open_ports or 8080 in open_ports:
        result_box.insert("end", "Potential vulnerability: HTTP port is open. Ensure the server is secured.\n")
        vulnerabilities += 1
    if not open_ports:
        result_box.insert("end", "No known vulnerabilities detected.\n")

    return vulnerabilities

# Action for the Scan button
def start_scan():
    local_ip = get_local_ip()
    network = str(ipaddress.IPv4Network(local_ip + '/24', strict=False).network_address) + "/24"

    def network_scan():
        devices = scan_network(network, result_box)
        total_vulnerabilities = 0
        total_devices = len(devices)
        
        for device in devices:
            ip = device['ip']
            total_vulnerabilities += check_vulnerabilities(ip, result_box)
        
        # Calculate the score based on the findings
        score = calculate_network_score(total_devices, total_vulnerabilities)
        
        # Display the final score
        result_box.insert("end", f"\nNetwork security rating: {score}/10\n")

    scan_thread = Thread(target=network_scan)
    scan_thread.start()

# Function to calculate the score based on the network scan
def calculate_network_score(total_devices, total_vulnerabilities):
    max_devices = 20  # Assuming maximum of 20 devices for a score of 10
    max_vulnerabilities = 5  # Assuming maximum of 5 vulnerabilities for a score of 0

    # Calculate the score based on devices and vulnerabilities
    device_score = min(total_devices, max_devices) / max_devices * 5  # Max score based on devices
    vulnerability_score = max(0, max_vulnerabilities - total_vulnerabilities) / max_vulnerabilities * 5  # Max score based on vulnerabilities

    total_score = device_score + vulnerability_score
    return round(total_score)

# Function to open the GitHub link
def open_github():
    webbrowser.open("https://github.com/nefariousjosiah")  # Replace with your GitHub URL

# GUI Setup
app = ctk.CTk()
app.title("Network Scanner and Vulnerability Detector")
app.geometry("700x600")

# Header
label_header = ctk.CTkLabel(app, text="Network Scanner & Vulnerability Detector", font=ctk.CTkFont(size=20, weight="bold"))
label_header.pack(pady=10)

# Network Entry
frame_network = ctk.CTkFrame(app)
frame_network.pack(pady=10, padx=20, fill="x")

label_network = ctk.CTkLabel(frame_network, text="Enter Network Range:")
label_network.pack(side="left", padx=10)

entry_network = ctk.CTkEntry(frame_network, placeholder_text="e.g., 192.168.1.0/24")
entry_network.pack(side="left", padx=10, fill="x", expand=True)

button_scan = ctk.CTkButton(frame_network, text="Scan Network", command=start_scan)
button_scan.pack(side="left", padx=10)

# Results Box
result_box = ctk.CTkTextbox(app, width=600, height=400)
result_box.pack(pady=10, padx=20, fill="both", expand=True)

# Footer
label_footer = ctk.CTkLabel(app, text="Developed by Josiah", font=ctk.CTkFont(size=12, slant="italic"), text_color="blue")
label_footer.pack(pady=10)

# Make the footer clickable
label_footer.bind("<Button-1>", lambda e: open_github())

# Run the app
app.mainloop()
