# WindowSOPS - Windows Security Operations & Audit Tool

**Author:** HaruShinono  
**Version:** 3.3 (Stable)  
**Language:** Batch / PowerShell  

## 🛡️ Overview

**WindowSOPS** is a lightweight, standalone security auditing tool designed for Windows System Administrators and Forensic Analysts. It combines the speed of native Batch commands with the power of PowerShell to perform deep system analysis, detect suspicious activities, and audit security configurations without requiring external installation.

It automatically generates a detailed log file for every session, ensuring you have a record of the audit.

## 🚀 Features

WindowSOPS includes 8 powerful modules:

1.  **Deep System Audit**: Retrieves hardware info, OS version, disk space status, and IP/Mac configurations.
2.  **Security Check**: Verifies Windows Defender status (Service & Real-time protection), Firewall profiles, and UAC levels.
3.  **Process Analysis**:
    *   Scans for **LOLBins** (Living Off The Land Binaries) often used by attackers (e.g., `powershell`, `rundll32`, `bitsadmin`).
    *   Identifies the top 5 processes consuming the most RAM.
4.  **Network Analysis**: Checks active `ESTABLISHED` connections, dumps the DNS Cache, and inspects the Routing Table.
5.  **Advanced Port Scanner**:
    *   **Quick Scan**: Checks top 20 common ports.
    *   **Custom Range**: Allows scanning specific port ranges.
    *   **Localhost Check**: Self-diagnostic scan.
    *   *Note: Features color-coded output (Green=Open).*
6.  **User & Privilege Audit**: Lists Local Administrators, all user accounts, and checks the status of the Guest account.
7.  **Event Log Analysis**:
    *   Extracts the last 5 Failed Login attempts (Event ID 4625).
    *   Extracts recent User Creation events (Event ID 4720).
8.  **Integrity & Update Status**: Checks for pending reboots, lists the last 10 installed Hotfixes, and runs System File Checker (`sfc`).

## 📋 Menu Options

```text
[1] Deep System Audit (HW, IP, Disk)
[2] Security Check (Firewall, AV, UAC)
[3] Process Analysis (Suspicious, High RAM)
[4] Network Analysis (Connections, Routes)
[5] Advanced Port Scanner
[6] User and Privilege Audit
[7] Event Log Analysis (Logins, Creations)
[8] Integrity and Update Status
[9] Open Report
[G] GitHub
[Q] Exit
```
## ⚙️ Installation & Usage
1.  Download the source code.
2.  Save the file with a .bat extension (e.g., WindowSOPS.bat).
3.  Right-click the file and select "Run as Administrator".
*  Note: Admin privileges are required to access Event Logs, System Files, and Network details.
## 📂 Logging
The tool automatically saves a report file named WS_Report.txt.
*  Default Location: The same folder where the script is located.
*  Fallback Location: If the script is run from a protected folder (like System32), the log is saved to %TEMP%\WS_Report.txt.
## ⚠️ Disclaimer
This tool is provided for educational and administrative purposes only. I am not responsible for any misuse or damage caused by this tool. Always ensure you have permission to audit the target system.
