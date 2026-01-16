# Playbook.md

## CCDC 2026 Network Topology Overview

```
                    [INTERNET]
                        |
                172.31.21.2/29 (external)
                   [VyOS Router v1.4.3]
                   /              \
        172.16.101.1/24      172.16.102.1/24
              |                    |
    [Palo Alto v11.0.2]    [Cisco FTD v7.2.9]
    outside: .254/24        outside: .254/24
    inside: 172.20.242.254  inside: 172.20.240.254
              |                    |
     DMZ-1 (242.0/24)       DMZ-2 (240.0/24)
     ├─ Ecom (.30)          ├─ AD/DNS (.102)
     ├─ Webmail (.40)       ├─ Web (.101)
     ├─ Splunk (.20)        ├─ FTP (.104)
     └─ Ubuntu Wks (DHCP)   └─ Win11 Wks (.100)
```

## Critical First Actions (Do These Immediately)

### 1. Change ALL Default Credentials
Every system has weak/default credentials. Priority order:

| Device | Current Creds | Change Command/Method |
|--------|--------------|----------------------|
| VyOS Router | vyos:changeme | `configure` → `set system login user vyos authentication plaintext-password 'NEWPASS'` |
| Palo Alto | admin:Changeme123 | Web UI: Device → Administrators |
| Cisco FTD | admin:!Changeme123 | FDM UI: System → Users |
| Splunk | admin:changeme | Web UI: Settings → Users |
| All Linux | sysadmin:changeme | `passwd sysadmin` |
| All Windows | administrator:!Password123 | `net user administrator NEWPASS` |

---

## VyOS Router Hardening (172.31.21.2)

### Access Control Lists (Critical)
```bash
configure

# === INBOUND FROM INTERNET ===
set firewall ipv4 name WAN-TO-LAN default-action drop
set firewall ipv4 name WAN-TO-LAN enable-default-log

# Allow established/related
set firewall ipv4 name WAN-TO-LAN rule 1 action accept
set firewall ipv4 name WAN-TO-LAN rule 1 state established 
set firewall ipv4 name WAN-TO-LAN rule 1 state related 

# Allow HTTP/HTTPS to web servers (NAT targets)
set firewall ipv4 name WAN-TO-LAN rule 100 action accept
set firewall ipv4 name WAN-TO-LAN rule 100 destination port 80,443
set firewall ipv4 name WAN-TO-LAN rule 100 protocol tcp
set firewall ipv4 name WAN-TO-LAN rule 100 log 

# Allow SMTP/IMAP to webmail
set firewall ipv4 name WAN-TO-LAN rule 110 action accept
set firewall ipv4 name WAN-TO-LAN rule 110 destination port 25,587,993,143
set firewall name WAN-TO-LAN rule 110 protocol tcp
set firewall ipv4 name WAN-TO-LAN rule 110 log 

# Allow FTP (passive mode range)
set firewall ipv4 name WAN-TO-LAN rule 120 action accept
set firewall ipv4 name WAN-TO-LAN rule 120 destination port 21,40000-40100
set firewall ipv4 name WAN-TO-LAN rule 120 protocol tcp
set firewall ipv4 name WAN-TO-LAN rule 120 log 

# Drop and log everything else
set firewall ipv4 name WAN-TO-LAN rule 999 action drop
set firewall ipv4 name WAN-TO-LAN rule 999 log

# Define zones 
set firewall zone WAN default-action drop                set firewall zone LAN default-action drop                                         
# Assign interfaces to zones                           
set firewall zone WAN interface eth0                     set firewall zone LAN interface eth1                     set firewall zone LAN interface eth2                     

# Apply your ruleset between zones 
set firewall zone LAN from WAN firewall name WAN-TO-LAN  

commit
save
```

### Egress Filtering (Detect C2)
```bash
# Block common C2 ports outbound
set firewall ipv4 name LAN-TO-WAN default-action accept
set firewall ipv4 name LAN-TO-WAN rule 10 action drop
set firewall ipv4 name LAN-TO-WAN rule 10 destination port 4444,5555,6666,1337,31337
set firewall ipv4 name LAN-TO-WAN rule 10 protocol tcp
set firewall ipv4 name LAN-TO-WAN rule 10 log 

# Block IRC (common C2)
set firewall ipv4 name LAN-TO-WAN rule 20 action drop
set firewall ipv4 name LAN-TO-WAN rule 20 destination port 6667,6697
set firewall ipv4 name LAN-TO-WAN rule 20 protocol tcp
set firewall ipv4 name LAN-TO-WAN rule 20 log 

# Log all outbound DNS (for exfil detection)
set firewall ipv4 name LAN-TO-WAN rule 30 action accept
set firewall ipv4 name LAN-TO-WAN rule 30 destination port 53
set firewall ipv4 name LAN-TO-WAN rule 30 log 
```

---

## Palo Alto Firewall Hardening (172.20.242.150)

### Immediate Actions via Web UI
1. **Device → Setup → Management → General Settings**
   - Change hostname

2. **Device → Administrators**
   - Change admin password

3. **Device → Authentication Profile**
   - Set lockout (5 attempts, 30 min)

4. **Device → Setup → Management → Authentication Settings**
   - Set session timeout: 10 minutes

### Security Policy Rules (Objects → Security Policies)
```
# Rule structure: Name | Source | Destination | Application | Action | Log

1. "Block-Known-Bad" | any | any | [malware-category] | deny | log-end
2. "Allow-Ecom-Inbound" | untrust | 172.20.242.30 | web-browsing,ssl | allow | log-both
3. "Allow-Webmail-Inbound" | untrust | 172.20.242.40 | smtp,imap,pop3 | allow | log-both
4. "Allow-Splunk-Internal" | 172.20.242.0/24 | 172.20.242.20 | tcp/8000,9997,8089 | allow | log-end
5. "Inter-Zone-Logging" | trust | untrust | any | allow | log-both
6. "Deny-All" | any | any | any | deny | log-end
```

### Threat Prevention Profile
```
Objects → Security Profiles → Vulnerability Protection
- Create profile "CCDC-Block"
- Set all severities to "block" or "reset-both"
- Enable packet capture for critical

Objects → Security Profiles → Anti-Spyware
- Block on all severity levels
- Enable DNS sinkhole: 172.20.242.1 (fake IP for logging)

Apply profiles to all Allow rules
```

### Logging Configuration (Critical for Splunk)
```
Device → Log Settings → System
- Severity: Informational and above
- Forward to Splunk: 172.20.242.20:9997

Objects → Log Forwarding → Create "CCDC-Logs"
- Traffic: Send to Splunk
- Threat: Send to Splunk
- URL: Send to Splunk
- Auth: Send to Splunk

Apply log forwarding profile to all security rules
```

### Zone Protection Profile
```
Network → Zone Protection → Create "Edge-Protection"
- Flood Protection:
  - SYN: Alert 10000, Activate 20000, Maximum 40000
  - UDP: Alert 10000, Activate 20000
  - ICMP: Alert 1000, Activate 2000
- Reconnaissance Protection:
  - TCP Port Scan: Block-IP (60 seconds)
  - Host Sweep: Block-IP (60 seconds)

Apply to "untrust" zone
```

---

## Cisco FTD Hardening (172.20.240.200)

### FDM Web Interface (https://172.20.240.200)

### Access Control Policy
```
Policies → Access Control → Create Rules

1. Name: "Block-Malicious"
   Source: any | Dest: any | Action: Block
   Enable IPS policy: "Balanced Security and Connectivity"
   Logging: Log at End

2. Name: "Allow-AD-DNS"
   Source: inside | Dest: 172.20.240.102 | Ports: DNS over UDP, Kerberos (udp,88), LDAP, LDAPS(tcp,636), MicrosoftDS (tcp,445)
   Action: Allow | Logging: Log at End

3. Name: "Allow-Web-Inbound"
   Source: outside | Dest: 172.20.240.101 | Ports: HTTP, HTTPS
   Action: Allow | Logging: Log at Beginning and End

4. Name: "Allow-FTP-Inbound"
   Source: outside | Dest: 172.20.240.104 | Ports: FTP, FTP High Ports(tcp,40000-40100)
   Action: Allow | Logging: Log at End

5. Name: "Default-Deny"
   Source: any | Dest: any | Action: Block
   Logging: Log at Beginning and End
```

### NAT Configuration
```
Policies → NAT → Manual NAT Rules

# Inbound NAT for scored services
- Original: outside/any → outside-IP:80
  Translated: inside/172.20.240.101:80

# Outbound PAT for internal hosts
- Original: inside/172.20.240.0/24 → any
  Translated: outside/interface
```

### Intrusion Policy
```
Policies → Intrusion → Edit "Balanced Security"
- Set action: Drop for all High/Critical severity
- Enable network-based malware detection
- Apply to all Allow rules in Access Control Policy
```

### Syslog Configuration for Splunk (Step-by-Step)

**Step 1: Create Syslog Server Object**
```
Objects → Syslog Servers → Add (+)

Field               | Value
--------------------|------------------------
IP Address          | 172.20.242.20
Port                | 514 (UDP) or 9997 (TCP)
Protocol            | UDP or TCP
Interface           | inside
```

**Step 2: Configure Logging Settings**
```
Device → System Settings → Logging Settings

- Enable Logging: ✓ (checked)
- Syslog Server: Select server created above

Logging Levels:
- FTD Event Log:      Informational
- Connection Events:  Informational
- Intrusion Events:   Alerts
- File/Malware:       Informational
```

**Step 3: Enable Logging on Access Control Rules**
```
Policies → Access Control → [Edit Each Rule] → Logging tab

- Log at Beginning of Connection: ✓ (optional, increases volume)
- Log at End of Connection: ✓ (required)
- Send Connection Events to: Syslog Server
```

**Step 4: Configure Connection Event Logging**
```
Policies → Access Control → Logging Settings (gear icon)

- Select syslog server for connection events
- Enable logging for:
  ✓ Connections matching rules
  ✓ Connections blocked by default action
```

**Step 5: Deploy Changes**
```
Deploy → Deploy Now
```

### CLI Alternative (via SSH/Console)
```
configure terminal
logging enable
logging host inside 172.20.242.20
logging trap informational
logging permit-hostdown
logging timestamp
end
write memory
```

### Verify Logs Arriving in Splunk
```spl
index=firewall sourcetype=cisco:ftd
| stats count by src_ip, dest_ip, action
```

---

## Splunk Server Hardening (172.20.242.20)

### Access Control (Immediate)
```bash
# Change all default passwords
passwd root
passwd sysadmin

# Splunk Web admin password
/opt/splunk/bin/splunk edit user admin -password 'NEWSTRONGPASS' -auth admin:changeme

# Restrict Splunk management port
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="172.20.242.0/24" port port="8000" protocol="tcp" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="172.20.240.0/24" port port="8000" protocol="tcp" accept'
sudo firewall-cmd --permanent --remove-service=http
sudo firewall-cmd --reload
```

### Splunk Configuration Files

/opt/splunk/etc/system/local/inputs.conf**
```ini
[default]
host = splunk-ccdc

# Receive logs from forwarders
[splunktcp://9997]
disabled = 0
connection_host = ip

# Syslog from firewalls
[udp://514]
disabled = 0
sourcetype = syslog
connection_host = ip

# Monitor local auth logs
[monitor:///var/log/secure]
disabled = 0
sourcetype = linux_secure
index = os

[monitor:///var/log/messages]
disabled = 0
sourcetype = syslog
index = os
```

**$SPLUNK_HOME/etc/system/local/outputs.conf**
```ini
[indexAndForward]
index = true

[tcpout]
defaultGroup = none
```

### Critical Indexes to Create (via GUI)
```
Settings → Indexes → New Index

Index Name    | Purpose
--------------|---------------------------
firewall      | Palo Alto and FTD logs
windows       | Windows event logs
linux         | Linux syslogs
network       | Router/switch logs
threat        | IDS/IPS alerts
```

### Configure Data Inputs via GUI (Receive Firewall Logs)

**Step 1: Create Firewall Index**
```
Settings → Indexes → New Index

Field          | Value
---------------|------------------
Index Name     | firewall
Max Size       | 500 MB
App            | Search & Reporting

Click Save
```

**Step 2: Add UDP Data Input (Syslog)**
```
Settings → Data Inputs → UDP → Add New

Field                        | Value
-----------------------------|------------------
Port                         | 514
Source name override         | (leave blank)
Only accept connection from  | (leave blank)

Click Next

Input Settings:
Field          | Value
---------------|------------------
Source type    | Select → Network & Security → syslog
Index          | firewall

Click Review → Submit
```

**Step 3: Add TCP Data Input (Alternative)**
```
Settings → Data Inputs → TCP → Add New

Field          | Value
---------------|------------------
Port           | 9997
Source type    | syslog
Index          | firewall

Click Review → Submit
```

**Step 4: Install Firewall Add-ons (Recommended)**
```
Apps → Find More Apps

Search and install:
- Palo Alto Networks Add-on for Splunk
- Cisco Firepower Add-on for Splunk

These provide proper field extraction and dashboards.
```

**Step 5: Restart Splunk**
```
Settings → Server Controls → Restart Splunk
```

**Step 6: Open Firewall Ports on Splunk Server**
```bash
sudo firewall-cmd --permanent --add-port=514/udp
sudo firewall-cmd --permanent --add-port=9997/tcp
sudo firewall-cmd --reload
```

**Step 7: Verify Logs Arriving**
```spl
index=firewall
| stats count by sourcetype, host
```

### Log Integrity
```bash
# Enable index signing
# $SPLUNK_HOME/etc/system/local/indexes.conf
[main]
enableDataIntegrityControl = true

# All custom indexes
[firewall]
enableDataIntegrityControl = true
homePath = $SPLUNK_DB/firewall/db
coldPath = $SPLUNK_DB/firewall/colddb
thawedPath = $SPLUNK_DB/firewall/thaweddb
```

---

## Splunk Detection & Alerting Strategy

### Priority 1: Authentication Attacks

**Failed Login Surge (Brute Force)**
```spl
index=* (sourcetype=linux_secure OR sourcetype=WinEventLog:Security)
("Failed password" OR EventCode=4625)
| stats count by src_ip, dest, user
| where count > 10
| table _time, src_ip, dest, user, count
```
Alert: Trigger when count > 10 in 5 minutes

**Successful Login After Failures**
```spl
index=* sourcetype=linux_secure "Accepted password"
| join src_ip [search index=* sourcetype=linux_secure "Failed password"
| stats count as failures by src_ip | where failures > 5]
| table _time, src_ip, user, failures
```

**New Admin Account Created**
```spl
index=windows EventCode=4720 OR EventCode=4728 OR EventCode=4732
| table _time, TargetUserName, SubjectUserName, Computer
```
Alert: Any new admin creation

### Priority 2: Network Anomalies

**Firewall Denied Traffic Spikes**
```spl
index=firewall action=denied OR action=drop
| timechart span=1m count by src_ip
| where count > 100
```

**Outbound Connection to Unusual Ports**
```spl
index=firewall direction=outbound dest_port!=80 dest_port!=443 dest_port!=53 dest_port!=25
| stats count by src_ip, dest_ip, dest_port
| where count > 5
| table src_ip, dest_ip, dest_port, count
```

**DNS Exfiltration Detection**
```spl
index=* sourcetype=pan:traffic application=dns
| eval query_length=len(query)
| where query_length > 50
| stats count by src_ip, query
| where count > 10
```

### Priority 3: System Compromise Indicators

**New Scheduled Tasks/Cron Jobs**
```spl
index=* ("crontab" OR EventCode=4698)
| table _time, host, user, CommandLine, TaskName
```

**Process Execution from Temp Directories**
```spl
index=* sourcetype=WinEventLog:Security EventCode=4688
| where like(NewProcessName, "%\\Temp\\%") OR like(NewProcessName, "%\\tmp\\%")
| table _time, Computer, SubjectUserName, NewProcessName, ParentProcessName
```

**Service Installation**
```spl
index=windows EventCode=7045
| table _time, Computer, ServiceName, ImagePath, ServiceType
```
Alert: Any new service

### Priority 4: Lateral Movement

**RDP/SSH to Multiple Hosts**
```spl
index=* (dest_port=3389 OR dest_port=22) action=allowed
| stats dc(dest_ip) as unique_targets by src_ip
| where unique_targets > 3
| table src_ip, unique_targets
```

**Pass-the-Hash Detection**
```spl
index=windows EventCode=4624 LogonType=3 AuthenticationPackage=NTLM
| stats count by src_ip, TargetUserName
| where count > 5
```

**SMB Connections Surge**
```spl
index=* dest_port=445 action=allowed
| timechart span=5m count by src_ip
| where count > 50
```

### Dashboard: CCDC Real-Time Operations

Create dashboard with panels:
1. Authentication Failures (last 15 min)
2. Top Denied IPs (firewall)
3. Outbound Connections by Port
4. New User/Service Creations
5. Critical Host Status
6. Traffic Volume by Zone

---

## Incident Response

See **[ir-playbook.md](ir-playbook.md)** for detailed incident response procedures including:
- Detection queries and Splunk searches
- Network and host-level containment
- Persistence removal checklists
- Recovery procedures
- Documentation templates

---

## Prioritized Hardening Checklist

### TIER 1: Do First (< 30 minutes)

- [ ] Change ALL default passwords (see credential table above)
- [ ] VyOS: Disable telnet, restrict SSH to internal
- [ ] Palo Alto: Enable logging, apply to all rules
- [ ] Cisco FTD: Enable logging to Splunk
- [ ] Splunk: Change admin password, restrict web UI access
- [ ] Verify all scored services are accessible

### TIER 2: Critical (< 2 hours)

- [ ] VyOS: Implement WAN-TO-LAN ACL
- [ ] VyOS: Implement egress filtering
- [ ] Palo Alto: Enable Threat Prevention profiles
- [ ] Palo Alto: Configure Zone Protection
- [ ] Cisco FTD: Enable IPS policy
- [ ] Splunk: Create critical alert dashboards
- [ ] All systems: Check for unauthorized users/SSH keys

### TIER 3: Important (< 4 hours)

- [ ] VyOS: Enable routing protocol authentication
- [ ] Palo Alto: Configure App-ID policies
- [ ] Splunk: Full alert ruleset implementation
- [ ] Linux hosts: Implement iptables baseline
- [ ] Windows hosts: Enable audit logging (4624, 4625, 4688, 4720)
- [ ] Document all changes made

### TIER 4: If Time Permits

- [ ] Implement DNS sinkhole for malware domains
- [ ] Configure log rotation policies
- [ ] Create host integrity baselines
- [ ] Test incident response procedures
- [ ] Cross-train team on each component

---

## Quick Reference: Management Access

| Device | Management IP | Port | Protocol |
|--------|--------------|------|----------|
| VyOS Router | 172.16.101.1 or 172.16.102.1 | 22 | SSH |
| Palo Alto | 172.20.242.150 | 443 | HTTPS |
| Cisco FTD | 172.20.240.200 | 443 | HTTPS |
| Splunk | 172.20.242.20 | 8000 | HTTPS |

## Quick Reference: Scored Services (Keep These UP!)

| Service | Host | IP | Port(s) |
|---------|------|-------|---------|
| E-Commerce | Ubuntu Ecom | 172.20.242.30 | 80, 443 |
| Webmail | Fedora | 172.20.242.40 | 25, 143, 993 |
| Web Server | Server 2019 | 172.20.240.101 | 80, 443 |
| FTP | Server 2022 | 172.20.240.104 | 21 |
| DNS | Server 2019 AD | 172.20.240.102 | 53 |
| Active Directory | Server 2019 AD | 172.20.240.102 | 88, 389, 636 |

---

## Red Team Common Techniques to Watch For

1. **Initial Access:** SSH brute force, web app exploitation, phishing
2. **Persistence:** Cron jobs, systemd services, Windows scheduled tasks, SSH keys
3. **Privilege Escalation:** SUID binaries, kernel exploits, token manipulation
4. **Lateral Movement:** Pass-the-hash, RDP, SSH key reuse, psexec
5. **Exfiltration:** DNS tunneling, HTTPS to unusual IPs, large outbound transfers
6. **Defense Evasion:** Log clearing, timestomping, firewall rule changes

---

## Emergency Contacts During Competition

Document your team's communication channels here:
- Team Captain:
- Network Lead (Router/Firewall):
- Windows Lead:
- Linux Lead:
- Splunk/Monitoring:
