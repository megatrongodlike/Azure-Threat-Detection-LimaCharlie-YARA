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
