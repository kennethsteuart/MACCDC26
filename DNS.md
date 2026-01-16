# System Administration & Incident Response Guide

## Core Tools
* **DNS:** Domain Name System management.
* **LSOF:** List Open Files (used to see what processes use which files/ports).
* **PS:** Process Status (listing running processes).
* **NMAP:** Network Mapper (network discovery and security auditing).

---

## Phase 1: Check if DNS is Running
Before troubleshooting, verify the service status and network listening ports.

### Linux (Bind9 / Named)
1.  **Check Service Status:**
    ```bash
    systemctl status named
    # OR
    service bind9 status
    ```
2.  **Test Functionality (Local & Remote):**
    Use `dig` or `nslookup` to verify resolution.
    ```bash
    dig @localhost google.com
    ```
3.  **Check Listening Ports:**
    Ensure port **53** (TCP/UDP) is open.
    ```bash
    ss -tunlp | grep :53
    # Note: lsof is also a tool used here
    lsof -i :53
    ```

### Windows Server (DNS Role)
1.  **Check Service Status (PowerShell):**
    ```powershell
    Get-Service DNS
    ```
2.  **Test Functionality:**
    ```powershell
    Resolve-DnsName google.com -Server 127.0.0.1
    ```

---

## Phase 2: Network Discovery (NMAP)
Use NMAP to audit the network and verify what is actually visible.

* **Scan a single IP for open ports:**
    ```bash
    nmap 192.168.1.10
    ```
* **Detect Service Versions:**
    (Identifies outdated software versions)
    ```bash
    nmap -sV 192.168.1.10
    ```
* **Detect Operating System:**
    ```bash
    nmap -O 192.168.1.10
    ```
* **Scan a whole subnet (Host Discovery):**
    (Finds live hosts without port scanning)
    ```bash
    nmap -sn 192.168.1.0/24
    ```

---

## Phase 3: Access & Repair (DNS Server)
Once an issue is identified, access the server to apply fixes.

### How to Access
* **Linux:** Use SSH (Secure Shell).
    ```bash
    ssh username@server_ip_address
    ```
* **Windows:** Use RDP (Remote Desktop Protocol) or PowerShell Remoting (WinRM).

### Common Fixes

#### 1. Restart the Service
* **Linux:**
    ```bash
    systemctl restart named
    ```
* **Windows:**
    ```powershell
    Restart-Service DNS
    ```

#### 2. Check Configuration Syntax
* **Linux:** (Validates configuration files for typos)
    ```bash
    named-checkconf /etc/named.conf
    ```

#### 3. Flush DNS Cache
* **Windows:**
    ```powershell
    Clear-DnsServerCache
    ```
* **Linux:**
    ```bash
    rndc flush
    ```

---

## Phase 4: Incident Response (Eviction)
If an unauthorized user is detected, remove access immediately.

### Step 1: Identification
* **Linux:** Type `w` or `who` to see logged-in users.
* **Windows:** Use Task Manager (Users tab) or run `query user` in CMD.

### Step 2: Termination (Kicking them off)
* **Linux:**
    1.  Find the **PID** (Process ID) via `w` or `ps`:
        ```bash
        ps -aux | grep ssh
        ```
    2.  Kill the session:
        ```bash
        kill -9 [PID]
        # OR
        pkill -KILL -u [username]
        ```
* **Windows:**
    1.  Get the **Session ID** from `query user`.
    2.  Log them off:
        ```cmd
        logoff [SessionID]
        ```

### Step 3: Lock the Door (Immediate Mitigation)
1.  **Change Passwords:** Immediately reset the compromised account's password.
2.  **Firewall Block:**
    * **Linux:**
        ```bash
        iptables -A INPUT -s [Attacker_IP] -j DROP
        ```
    * **Windows:** Create a new Rule in "Windows Defender Firewall with Advanced Security" to block the remote IP.
3.  **Isolate:** If deeply compromised, physically unplug the network cable (or disconnect vNIC) to prevent lateral movement.

---

## Phase 5: Forensics (Root Cause Analysis)
Analyze how the breach occurred to prevent recurrence.

### Linux Log Analysis
**Location:** Usually `/var/log/`
* **Key Files:**
    * `/var/log/auth.log` (or `/var/log/secure`): SSH logins, sudo usage, auth failures.
    * `/var/log/syslog`: General system activity.
    * `/var/log/apache2/access.log`: Web server access logs.
* **Investigation Tools:**
    ```bash
    # Watch logs in real-time
    tail -f /var/log/auth.log

    # Find brute force attempts
    grep "Failed password" /var/log/auth.log

    # Show history of last logged-in users
    last
    ```

### Windows Log Analysis
**Tool:** Event Viewer (`eventvwr.msc`)
* **Key Logs:**
    * **Security Log:** Event ID **4624** (Success) and **4625** (Failed Logon).
    * **System Log:** Service changes or shutdowns.
* **PowerShell/Sysmon:** Detailed command execution logs.
* **Search via PowerShell:**
    ```powershell
    Get-EventLog -LogName Security -InstanceId 4625 -Newest 20
    ```

### How to Determine the Entry Point
1.  **Check Logon Times:** Look for logins at odd hours (e.g., 3 AM) from foreign IPs.
2.  **Check Web Logs:** Did they access a file upload page immediately before the breach? (Indicates web shell/vulnerability).
3.  **Check Bash History:** Look at `.bash_history` for the compromised user to see what commands the attacker ran.
4.  **Check Persistence (Backdoors):**
    * **Linux:** Check cron jobs (`crontab -l`) and `/etc/rc.local`.
    * **Windows:** Check Task Scheduler and Registry "Run" keys.
