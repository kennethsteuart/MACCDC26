# Administrative Playbook

## Team Leader Checklist (Before Competition)

- Get the team together, make sure all roles are assigned
- Linux/Windows administrative teams are aware of their playbooks and have read them over before competition
- Any documentation officers should be assigned to taking notes on any important information from hardening stages in the first hour (password policies, ports that were open then closed, firewalls setup, take notes of auditing stages and logs)
- Documentation/Floaters should also keep track of lockouts and help with monitoring as well to be an extra set of eyes

## Team Leader Checklist (During Competition)

Make sure each team is following the time constraints and try not to spend too much time on one section.

### Team Assignments

Each team has their individual playbooks marked on different tabs and teams consist as follows:

- **Linux PB:** Rivers, Danny
- **Windows PB:** Mason, Alana, Jordan
- **Palo Alto + Splunk PB:** Connor, Joe
- **Documentation:** Kara

Below is a streamlined version of what to do during each 10 minute increment. The other three playbooks are specific to Linux vs Windows and each "flavor".

---

## Timeline

### First 10 Minutes

- Go to each team back & forth and establish what servers we have and what roles are made
- Set up everything to default deny on all systems
- Identify what servers we have (LINUX/Windows) and what distribution we have as well (Fedora/Debian/Ubuntu/RHEL)
- Along with identifying what users and roles are set

### 11-20 Minutes

Ensure all password policies are reset to be more complex on all systems:

- Admin above 20 chars
- Standard users above 12-14 chars
- Don't use pattern passwords
- Don't use restricted space (uppercase, followed by lowercase, then number)
- Rename all accounts
- Change passwords

### 21-30 Minutes

- Disable print spooler
- Disable client and server side SMBv1
- All drives no autorun

### 31-40 Minutes

**Credential and protocol hardening (LSA, NTLMv2, netBIOS/LLMNR):**

- Enable LSA (Local Security Authority) protection
- LAN manager refuse LM and NTLM
- Turn off LLMNR (Link Local Multicast Name Resolution) - DNS
- NetBT nodetype p-node

### 41-50 Minutes

**Advanced auditing (what to log, how to see it fast):**

- Force subcategory audits to override legacy
- Enable (success/failure as noted):
  - Credential validation (S/F)
  - Logon (S/F)
  - Logoff (S)
  - Account lockout (F)
  - Special logon (S)
  - Process creation (S) <include command line>
  - File share (S/F)
  - Detailed file share (F)
  - Removable storage (S/F)
  - MPSSVC rule-level policy change (S/F)
  - Policy change (S)
  - Sensitive privilege use (S/F)
  - System integrity (S/F)

### 51-55 Minutes

**Allow-lists only (RDP from jump, require service ports):**

- Add only required inbound rules
- No any remote address
- No any/any
- No temporary broad rules
- `get-netfirewallprofile`

### 56-60 Minutes

**Verify, snapshot, evidence:**

- `auditpol /get /category:*`
- Confirm auditing
- Spooler stopped/disabled
- SMBv1 disabled
- Export secedit config
