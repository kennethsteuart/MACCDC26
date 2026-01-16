# Palo Alto Firewall + Splunk Server Hardening Guide

A comprehensive hardening guide for securing Palo Alto firewalls and Splunk servers in competitive cybersecurity environments.

---

## Table of Contents

- [Pre-Flight & Role Assignment (0:00)](#pre-flight--role-assignment-000)
- [Palo Alto Firewall Baseline Hardening (1:00–10:00)](#palo-alto-firewall-baseline-hardening-10010-00)
- [Splunk Server Access Hardening (11:00–20:00)](#splunk-server-access-hardening-110020-00)
- [Attack Surface Removal (21:00–30:00)](#attack-surface-removal-210030-00)
- [Credential & Protocol Hardening (31:00–40:00)](#credential--protocol-hardening-310040-00)
- [Logging Pipeline to Splunk (41:00–50:00)](#logging-pipeline-to-splunk-410050-00)
- [Zero-Trust Cleanup (51:00–55:00)](#zero-trust-cleanup-510055-00)
- [Verification & Evidence (56:00–60:00)](#verification--evidence-560060-00)

---

## Pre-Flight & Role Assignment (0:00)

### Pre-Flight Checklist

- ✅ Confirm physical console access for both systems (competition environments often break RDP/SSH)
- ✅ Identify jump box IP and force all admin access through it
- ✅ Record:
  - Firewall management IP
  - Splunk server IP
  - Subnets/VLANs
  - Default gateway
  - Known good DNS
- ✅ Check for signs of compromise:
  - Unknown admin accounts
  - Wide-open firewall rules
  - Unusual Splunk apps
- ✅ Create shared evidence folder on jump box

---

## Palo Alto Firewall Baseline Hardening (1:00–10:00)

### 1. Force Default Deny Everywhere

Palo Alto defaults to allow intra-zone traffic — you must change this.

**GUI Path:**
```
Network → Zones → (select each zone) → Intra-zone traffic → Deny
```

**CLI:**
```bash
configure
set zone trust network layer3 settings enable-user-identification no
set zone trust network layer3 intrusion-protection no
commit
```

### 2. Create Universal Deny Rule (Bottom of Rulebase)

```bash
configure
set rulebase security rules deny-all from any to any source any destination any application any service any action deny
commit
```

⚠️ Ensure this is NOT last; there must be no hidden vendor "Allow All" rule under it.

### 3. Enable Logging on Every Rule Immediately

Attackers hide in non-logging rules.

**GUI Path:**
```
Policies → Security → (edit each rule) → Actions tab → Enable:
  - Log at Session Start
  - Log at Session End
```

**CLI:**
```bash
set rulebase security rules <name> log-start yes
set rulebase security rules <name> log-end yes
commit
```

### 4. Mandatory Administrative Access Restrictions

Allow only management from your jump box:

```bash
set rulebase security rules mgmt-access \
    from trust to trust source <JUMP-IP> destination <FW-MGMT-IP> \
    application ssl,web-browsing \
    service application-default action allow
commit
```

Deny all other attempts:

```bash
set rulebase security rules block-mgmt \
    from any to trust destination <FW-MGMT-IP> \
    application any service any action deny
commit
```

### 5. Security Profiles Must Be Applied to All Allow Rules

(AV, Anti-Spyware, Vulnerability, URL Filtering)

**CLI:**
```bash
set profiles virus default action action-block
set profiles spyware default action action-block
set profiles vulnerability default action action-block
set profiles url-filtering default action block
commit
```

---

## Splunk Server Access Hardening (11:00–20:00)

### 1. Lock Down Linux SSH (Assuming Linux Server)

```bash
sudo passwd -l root
sudo sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### 2. Enforce Password Requirements

```bash
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 14/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
```

### 3. Firewall for Splunk Server (UFW)

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw allow 8000/tcp    # Splunk web
sudo ufw allow 8089/tcp    # Management API
sudo ufw allow 9997/tcp    # Forwarder ingestion
sudo ufw enable
```

### 4. Disable Unnecessary OS Services

```bash
sudo systemctl disable avahi-daemon --now
sudo systemctl disable cups --now
sudo systemctl disable rpcbind --now
sudo systemctl disable nfs --now
```

---

## Attack Surface Removal (21:00–30:00)

### A. Palo Alto: Block Critical Attack Vectors

These MUST be denied everywhere unless specifically required.

**SMB (very urgent):**
```bash
set rulebase security rules block-smb \
  from any to any application smb service any action deny
```

**RDP (allow only jump box → internal hosts):**
```bash
set rulebase security rules block-rdp \
  from any to any application ms-rdp action deny
commit
```

**Telnet:**
```bash
set rulebase security rules block-telnet from any to any application telnet action deny
```

**FTP:**
```bash
set rulebase security rules block-ftp from any to any application ftp action deny
```

### B. Splunk: Remove Attack Pivots

**Disable Default Web Apps:**
```bash
$SPLUNK_HOME/bin/splunk disable app sample_app
$SPLUNK_HOME/bin/splunk disable app legacy
$SPLUNK_HOME/bin/splunk disable app search_tutorial
$SPLUNK_HOME/bin/splunk restart
```

**Verify No Rogue Forwarders:**
```bash
$SPLUNK_HOME/bin/splunk list forward-server
```

---

## Credential & Protocol Hardening (31:00–40:00)

### A. Palo Alto: Block Legacy Broadcast Protocols

**LLMNR:**
```bash
set rulebase security rules block-llmnr from any to any application llmnr action deny
```

**NetBIOS:**
```bash
set rulebase security rules block-netbios from any to any application netbios action deny
```

**mDNS:**
```bash
set rulebase security rules block-mdns from any to any application mdns action deny
```

### B. Palo Alto: Zone Protection Against Recon

```bash
set network zone-protection-profile zp-default flood syn enable yes
set network zone-protection-profile zp-default flood udp enable yes
set network zone-protection-profile zp-default reconnaissance tcp-port-scan enable yes
commit
```

### C. Splunk: Enable Compliance-Grade Logging

**Enable Splunk Audit Index:**
```bash
$SPLUNK_HOME/bin/splunk enable boot-start
$SPLUNK_HOME/bin/splunk restart
```

**Verify audit logs:**
```
index=_audit | stats count by action user
```

**File integrity:**
```bash
sudo chmod 600 $SPLUNK_HOME/etc/auth/*
sudo chown splunk:splunk $SPLUNK_HOME/etc/auth/*
```

---

## Logging Pipeline to Splunk (41:00–50:00)

### 1. Configure Palo Alto → Splunk Syslog

Make Splunk a syslog receiver on port 514/UDP.

**Palo Alto CLI:**
```bash
set deviceconfig system syslog-server <SPLUNK-IP> transport udp port 514
commit
```

**Forward Security Logs:**
```bash
set log-settings system critical syslog yes
set log-settings threat high syslog yes
set log-settings traffic log yes
commit
```

### 2. Splunk: Validate Ingest

```
index=pan* | head
index=_internal | stats count by source
```

### 3. Build Quick-Triage Dashboards

**Top denied sources:**
```
index=pan_traffic action=deny | top limit=20 src_ip
```

**Threats by signature:**
```
index=pan_threat | stats count by threat_name,src_ip,dest_ip
```

**Admin logins:**
```
index=_audit action="login attempt" | stats count by user,info
```

---

## Zero-Trust Cleanup (51:00–55:00)

### 1. Remove ANY/ANY Rules

Run this carefully:

```bash
delete rulebase security rules any-any
commit
```

Or find them:

```bash
show rulebase security | match "any"
```

### 2. Ensure All Allow Rules Have:

- **Application** = `application-default`
- **Source** = specific subnets (never "any")
- **Service** = `application-default`
- **Profiles** = `strict-profiles`

### 3. Ensure Allow RDP Only From Jump Box

```bash
set rulebase security rules allow-rdp \
  from trust source <JUMP-IP> to trust destination <HOSTS> \
  application ms-rdp service application-default action allow
commit
```

---

## Verification & Evidence (56:00–60:00)

### Palo Alto Evidence Commands

```bash
show running-config
show log traffic last-60-minutes
show log threat last-60-minutes
show session all
show management
```

**Export Config:**

GUI: 
```
Device → Setup → Operations → Export running config
```

CLI:
```bash
scp export configuration from running-config.xml to user@jumpbox:
```

### Splunk Evidence Commands

**Service Status:**
```bash
sudo systemctl status splunk
```

**Listening Ports:**
```bash
sudo netstat -tulnp | grep -E "8000|8089|9997|514"
```

**Audit Activity:**
```
index=_audit | sort -_time | head 20
```

**Backup Config:**
```bash
tar -czvf splunk-config.tar.gz $SPLUNK_HOME/etc
```

---

## Quick Reference Timeline

| Time | Task |
|------|------|
| 0:00 | Pre-flight checklist & role assignment |
| 1:00–10:00 | Palo Alto baseline hardening |
| 11:00–20:00 | Splunk server access hardening |
| 21:00–30:00 | Attack surface removal |
| 31:00–40:00 | Credential & protocol hardening |
| 41:00–50:00 | Logging pipeline to Splunk |
| 51:00–55:00 | Zero-trust cleanup |
| 56:00–60:00 | Verification & evidence collection |

---

## License

This guide is provided for educational and defensive security purposes only.

## Contributing

Feel free to submit issues and enhancement requests for this hardening guide.


