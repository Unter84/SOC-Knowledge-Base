# 🛡️ Playbook: DCSync Attack Detected

**Filename:** `playbook-dcsync-attack-detected.md`  
**Category:** Active Directory / Credential Access  
**Use Case:** Investigating alerts triggered by unauthorized Directory Replication Service (DRS) requests (commonly used in DCSync attacks).

---

## 🎯 Alert Context — Why this matters
- **DCSync** is an adversary technique where a system impersonates a Domain Controller (DC) and requests password replication using DRS protocols.  
- **Impact:** Exposes NTLM hashes, Kerberos keys, and even the KRBTGT account → enables Golden Tickets, Pass-the-Hash, and domain compromise.  
- **Risk Level:** Critical.  

**Relevant Detection Sources:**
- Windows Security Logs (Event ID 4662, 4673, 4742)  
- Directory Service logs (Event IDs 4928, 4929 – replication requests)  
- EDR/XDR detections of Mimikatz, DCSync modules  
- Network logs for unusual LDAP/DRSR traffic  

---

## 🧭 Analyst Actions (L1 → L2 → L3)

### L1 — Initial Triage
- ✅ Capture alert details: account, source IP/hostname, target DC, timestamp.  
- ✅ Verify whether account used is **Domain Admin, Enterprise Admin, or a DC computer account**.  
- ✅ If **non-DC account** was used → suspicious.  
- ✅ Check source host — must be a DC for legitimate replication.  
- 🚩 Escalate to L2 if:
  - Account is not a DC or highly privileged account.  
  - Source is a workstation or non-DC server.  
  - Alert occurred outside expected change/test windows.  

**SPL — Detect DCSync Events**
```spl
index=wineventlog EventCode=4662
| search ObjectType="DS-Replication-Get-Changes*" 
| table _time ComputerName SubjectUserName SubjectDomainName ObjectType AccessMask


⸻

L2 — Deep Investigation

1. Account Analysis
	•	Identify which account requested replication.
	•	Confirm if it’s an expected privileged account or service.

index=wineventlog EventCode=4662
| stats count by SubjectUserName ObjectType AccessMask ComputerName

2. Source Host Verification
	•	Check whether the request originated from a legitimate DC.

index=wineventlog EventCode=4624
| search TargetUserName=<SuspiciousAccount>
| table _time IpAddress WorkstationName LogonType AuthenticationPackageName

3. Timeline Reconstruction
	•	Look for process creation linked to Mimikatz or PowerShell DCSync modules.

index=sysmon EventCode=1 host=<HOST>
| search CommandLine="*lsadump::dcsync*" OR CommandLine="*mimikatz*"
| table _time Image CommandLine ParentImage User

4. Directory Service Events
	•	Check Event IDs 4928/4929 (replication requests added/removed).

index=wineventlog EventCode=4928 OR EventCode=4929
| table _time ComputerName SubjectUserName ServicePrincipalName

5. Threat Intel
	•	Enrich source IP and file hashes (if applicable) with VirusTotal / OTX / MISP.

⸻

L3 — Confirm & Respond

Containment
	•	Isolate the source host immediately.
	•	Disable or suspend the account used.

Eradication
	•	Investigate for credential dumping tools (Mimikatz, Cobalt Strike).
	•	Collect memory and forensic artifacts.
	•	Remove persistence mechanisms.

Recovery
	•	Reset credentials for Domain Admins and service accounts used on the host.
	•	Reset KRBTGT account password twice to invalidate forged tickets.
	•	Harden replication permissions to restrict to DC accounts only.

If False Positive:
	•	Some identity sync tools or backup agents may perform legitimate replication.
	•	Verify with infra/identity team.
	•	Document in allowlist if expected.

⸻

🧩 MITRE ATT&CK Mapping
	•	T1003.006 – OS Credential Dumping: DCSync
	•	T1003 – OS Credential Dumping
	•	T1078 – Valid Accounts
	•	T1098 – Account Manipulation
	•	T1021 – Remote Services (if stolen creds reused)

⸻

📝 Root Cause Analysis (RCA) Template

1) Executive Summary
	•	What happened: DCSync attempt detected from <HOST> using <ACCOUNT>.
	•	Impact: Potential theft of domain credential hashes.
	•	Disposition: <True Positive | False Positive>.

2) Timeline
	•	T0: DCSync alert triggered.
	•	T1: Account and source host reviewed.
	•	T2: Process and logon events correlated.
	•	T3: Containment & remediation executed.

3) Root Cause
	•	[Compromised privileged account | Unauthorized replication | Misconfigured service account | Legitimate replication activity].

4) Scope
	•	Accounts queried, DCs targeted, any lateral movement indicators.

5) Actions Taken
	•	Containment, account disablement, forensic review, password resets.

6) Preventive Measures
	•	Restrict replication rights to DC accounts only.
	•	Monitor for 4662 events with DS-Replication permissions.
	•	Implement Just-In-Time Admin for privileged accounts.

7) Lessons Learned
	•	Improve SIEM rules for correlation.
	•	Validate inventory of accounts with replication rights.

⸻

🛡 Recommendations
	•	Immediate
	•	Isolate suspicious source host.
	•	Disable compromised account.
	•	Reset KRBTGT account (twice).
	•	Hardening
	•	Remove replication rights from non-DC accounts.
	•	Use Microsoft Protected Users group.
	•	Enforce LSASS protection (RunAsPPL).
	•	Apply tiered admin model.
	•	Monitoring
	•	Alert on Event ID 4662 with ObjectType = DS-Replication-Get-Changes* where SubjectUserName ≠ DC account.
	•	Monitor for suspicious PowerShell/Mimikatz usage.
	•	Watch for unusual LDAP/DRSR traffic patterns.

⸻

📎 Before Escalating to Customer

Provide:
	•	Account and host that initiated replication.
	•	Target DC(s).
	•	Evidence (Event IDs 4662, 4928/4929).
	•	Process/logon correlation (e.g., Mimikatz).
	•	Risk statement (potential domain compromise).
	•	Containment & remediation steps taken.

⸻
