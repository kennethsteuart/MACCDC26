# Incident Response Playbook

## Quick Reference: Network Topology
```
DMZ-1 (172.20.242.0/24)          DMZ-2 (172.20.240.0/24)
├─ Ecom (.30)                    ├─ AD/DNS (.102)
├─ Webmail (.40)                 ├─ Web (.101)
├─ Splunk (.20)                  ├─ FTP (.104)
└─ Ubuntu Wks (DHCP)             └─ Win11 Wks (.100)

Firewalls:
- Palo Alto: 172.20.242.254 (inside), 172.20.242.150 (mgmt)
- Cisco FTD: 172.20.240.254 (inside), 172.20.240.200 (mgmt)
- VyOS Router: 172.16.101.1, 172.16.102.1
```

---

## Phase 1: Detection

### Splunk Quick Queries

**Investigate Suspicious IP (run first)**
```spl
index=* src_ip="ATTACKER_IP" OR dest_ip="ATTACKER_IP"
| stats count by index, sourcetype, action
| sort -count
```

**User Activity Audit**
```spl
index=* user="COMPROMISED_USER"
| stats count by action, dest, sourcetype
| sort -count
```

**Host Activity Audit**
```spl
index=* host="COMPROMISED_HOST"
| timechart span=1m count by sourcetype
```

**Recent Authentication Failures**
```spl
index=* (sourcetype=linux_secure OR sourcetype=WinEventLog:Security)
("Failed password" OR EventCode=4625)
earliest=-30m
| stats count by src_ip, dest, user
| sort -count
```

**Outbound Connections (C2 Detection)**
```spl
index=firewall direction=outbound
dest_port!=80 dest_port!=443 dest_port!=53 dest_port!=25 dest_port!=123
earliest=-1h
| stats count by src_ip, dest_ip, dest_port
| sort -count
```

**New Processes from Temp Directories (Windows)**
```spl
index=windows EventCode=4688
| where like(NewProcessName, "%\\Temp\\%") OR like(NewProcessName, "%\\tmp\\%")
| table _time, Computer, SubjectUserName, NewProcessName, ParentProcessName
```

**New Services Installed**
```spl
index=windows EventCode=7045
| table _time, Computer, ServiceName, ImagePath, ServiceType
```

**New Scheduled Tasks**
```spl
index=* ("crontab" OR EventCode=4698)
| table _time, host, user, CommandLine, TaskName
```

---

## Phase 2: Containment

### Priority: STOP THE BLEEDING

#### Network-Level Blocks

**VyOS Router - Immediate Block**
```bash
configure
set firewall ipv4 name EMERGENCY default-action accept
set firewall ipv4 name EMERGENCY rule 1 action drop
set firewall ipv4 name EMERGENCY rule 1 source address ATTACKER_IP
set firewall ipv4 name EMERGENCY rule 1 log
set firewall zone WAN from LAN firewall name EMERGENCY
commit
save
```

**Palo Alto - Block Attacker**
```
1. Objects → Address Objects → Add
   Name: Blocked-Attacker
   IP: ATTACKER_IP

2. Policies → Security → Add (move to top)
   Name: Emergency-Block
   Source: Blocked-Attacker
   Destination: any
   Application: any
   Action: Deny
   Log: Log at Session End

3. Commit
```

**Cisco FTD - Block Attacker**
```
1. Objects → Networks → Add
   Name: Blocked-Attacker
   Value: ATTACKER_IP

2. Policies → Access Control → Add New Rule (drag to top)
   Name: Emergency-Block
   Source: Blocked-Attacker
   Destination: any
   Action: Block with reset
   Logging: Log at Beginning and End

3. Deploy → Deploy Now
```

#### Host-Level Isolation

**Linux - Isolate Host**
```bash
# Save current rules first
iptables-save > /tmp/iptables.backup

# Block all except SSH from admin workstation
iptables -F
iptables -A INPUT -s ADMIN_IP -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -j DROP
iptables -A OUTPUT -d ADMIN_IP -p tcp --sport 22 -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -j DROP
```

**Windows - Isolate Host**
```powershell
# Block all traffic except RDP from admin
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall firewall add rule name="Allow Admin RDP" dir=in action=allow protocol=tcp localport=3389 remoteip=ADMIN_IP
netsh advfirewall firewall add rule name="Allow Admin RDP Out" dir=out action=allow protocol=tcp localport=3389 remoteip=ADMIN_IP
```

#### Kill Active Sessions

**Linux - Kill User Sessions**
```bash
# List logged in users
who

# Kill specific user sessions
pkill -KILL -u MALICIOUS_USER

# Kill specific PID
kill -9 PID
```

**Windows - Kill User Sessions**
```powershell
# List sessions
query user

# Logoff session
logoff SESSION_ID

# Kill process
taskkill /F /PID PID_NUMBER
```

---

## Phase 3: Eradication

### Persistence Removal Checklist

#### Linux Systems

**Check Cron Jobs**
```bash
# User crontabs
crontab -l
crontab -l -u root
crontab -l -u sysadmin

# System crons
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
cat /etc/crontab
```

**Check Systemd Services**
```bash
# List enabled services
systemctl list-unit-files --state=enabled

# Look for suspicious services
systemctl list-units --type=service --state=running

# Check for user services
ls -la ~/.config/systemd/user/
```

**Check SSH Keys**
```bash
# Check all users
for user in $(cut -f1 -d: /etc/passwd); do
    home=$(eval echo ~$user)
    if [ -f "$home/.ssh/authorized_keys" ]; then
        echo "=== $user ==="
        cat "$home/.ssh/authorized_keys"
    fi
done
```

**Check for Backdoor Users**
```bash
# Users with UID 0
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Users with login shells
grep -v '/nologin\|/false' /etc/passwd

# Recently modified passwd/shadow
ls -la /etc/passwd /etc/shadow
```

**Check SUID Binaries**
```bash
find / -perm -4000 -type f 2>/dev/null
```

**Check /tmp and /var/tmp**
```bash
ls -la /tmp/
ls -la /var/tmp/
find /tmp -type f -executable
```

#### Windows Systems

**Check Scheduled Tasks**
```powershell
# List all tasks
schtasks /query /fo LIST /v

# Export for review
schtasks /query /fo CSV > C:\tasks.csv
```

**Check Services**
```powershell
# List services
Get-Service | Where-Object {$_.Status -eq "Running"}

# Check for unusual services
Get-WmiObject win32_service | Select-Object Name, PathName, StartMode | Format-List
```

**Check Startup Locations**
```powershell
# Registry Run keys
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# Startup folders
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
```

**Check Local Users**
```powershell
# List users
net user

# List admin group
net localgroup Administrators

# Check for hidden users ($ at end)
Get-WmiObject Win32_UserAccount | Select Name, Disabled, LocalAccount
```

**Check Network Connections**
```powershell
netstat -ano | findstr ESTABLISHED
netstat -ano | findstr LISTENING
```

---

## Phase 4: Recovery

### Service Verification Commands

| Service | Command |
|---------|---------|
| Ecom | `curl -I http://172.20.242.30` |
| Webmail | `curl -I http://172.20.242.40` |
| Web Server | `curl -I http://172.20.240.101` |
| FTP | `ftp 172.20.240.104` or `nc -zv 172.20.240.104 21` |
| DNS | `nslookup google.com 172.20.240.102` |
| AD | `ldapsearch -x -H ldap://172.20.240.102` |

### Remove Emergency Blocks

**VyOS - Remove Emergency Rule**
```bash
configure
delete firewall ipv4 name EMERGENCY
commit
save
```

**Palo Alto - Remove Block**
```
Policies → Security → Delete "Emergency-Block"
Commit
```

**Cisco FTD - Remove Block**
```
Policies → Access Control → Delete "Emergency-Block"
Deploy
```

**Linux - Restore Firewall**
```bash
iptables-restore < /tmp/iptables.backup
```

**Windows - Restore Firewall**
```powershell
netsh advfirewall reset
```

---

## Phase 5: Documentation

### Incident Report Template

```
INCIDENT REPORT
===============

Date/Time Detected:
Detected By:
Initial Indicators:

AFFECTED SYSTEMS
- Host:
- IP:
- Services Impacted:

ATTACKER INFORMATION
- Source IP(s):
- Methods Used:
- Persistence Mechanisms Found:

TIMELINE
[TIME] - Event description
[TIME] - Event description

ACTIONS TAKEN
1.
2.
3.

IOCs DISCOVERED
- IPs:
- File Hashes:
- User Accounts:
- File Paths:

SERVICE IMPACT
- Downtime Duration:
- Services Affected:

LESSONS LEARNED
-
```

---

## Quick Reference: Common Attack Patterns

### SSH Brute Force
**Indicators:**
- Many failed SSH attempts from same IP
- Successful login after failures

**Splunk Query:**
```spl
index=* sourcetype=linux_secure "Failed password"
| stats count by src_ip
| where count > 10
```

**Response:**
1. Block source IP at perimeter
2. Check if any logins succeeded
3. If yes, treat as compromised host

### Web Shell Upload
**Indicators:**
- POST requests to unusual file extensions
- New files in web directories
- Outbound connections from web server

**Response:**
1. Check web directories for new files
2. Review web server access logs
3. Remove malicious files
4. Patch vulnerability

### Privilege Escalation
**Indicators:**
- New admin users created
- SUID binary changes
- Sudo configuration changes

**Response:**
1. Remove unauthorized users
2. Restore sudo/SUID configs
3. Check for persistence mechanisms

### Lateral Movement
**Indicators:**
- RDP/SSH to multiple hosts from one source
- Pass-the-hash (NTLM auth from unusual sources)
- PSExec/WMI execution

**Response:**
1. Isolate source host
2. Reset compromised credentials
3. Check all contacted hosts for compromise

### Data Exfiltration
**Indicators:**
- Large outbound transfers
- DNS queries with long subdomains (tunneling)
- Connections to unusual external IPs

**Response:**
1. Block destination IPs/domains
2. Identify data accessed
3. Preserve evidence

---

## Emergency Contacts

| Role | Name | Contact |
|------|------|---------|
| Team Captain | | |
| Network Lead | | |
| Windows Lead | | |
| Linux Lead | | |
| Splunk/Monitoring | | |
