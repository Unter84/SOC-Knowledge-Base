

📌 Credential Dumping – Deep Dive

🔹 What is Credential Dumping?

Credential dumping is a post-exploitation technique used by attackers to extract authentication secrets (like usernames, passwords, hashes, Kerberos tickets, or plaintext credentials) from compromised systems.

The goal: gain persistence, escalate privileges, and move laterally across the environment.

Attackers don’t always need passwords in plaintext — sometimes a hash or ticket is enough (for Pass-the-Hash or Pass-the-Ticket attacks).

MITRE ATT&CK Technique: T1003 - OS Credential Dumping

⸻

🔹 Why Attackers Use It
	•	Bypass authentication (reuse or crack credentials).
	•	Escalate privileges (dumping local admin or domain admin credentials).
	•	Lateral movement (access file shares, RDP, VPN, cloud services).
	•	Establish long-term persistence (backdoors, domain dominance).

⸻

🔹 Techniques & Methods of Credential Dumping

Attackers use different methods depending on the system (Windows, Linux, macOS, cloud).

1. Windows Credential Dumping
	•	LSASS Process Memory (most common target):
	•	Tools: Mimikatz, ProcDump, comsvcs.dll
	•	Extracts plaintext passwords, hashes, Kerberos tickets from lsass.exe.
	•	SAM Database (Security Accounts Manager):
	•	Stored in C:\Windows\System32\config\SAM.
	•	Contains local user password hashes.
	•	Access requires SYSTEM-level privileges.
	•	NTDS.dit (Active Directory Database):
	•	Located on Domain Controllers.
	•	Contains all domain users’ credentials (hashes).
	•	Tools: ntdsutil, secretsdump.py (Impacket).
	•	DCSync Attack:
	•	Abuse of Directory Replication Service (DRSUAPI) to request password hashes from DCs.
	•	Doesn’t require direct file access.
	•	WDigest & Cached Credentials:
	•	If enabled, stores plaintext passwords in memory.
	•	LSA Secrets:
	•	Registry-stored credentials for services or scheduled tasks.

⸻

2. Linux Credential Dumping
	•	/etc/passwd & /etc/shadow files:
	•	Contain hashed credentials.
	•	Often exfiltrated for offline cracking.
	•	Credential caches:
	•	SSH private keys, Kerberos tickets (/tmp/krb5cc_*).
	•	Memory scraping:
	•	Tools like gcore, proc filesystem dumps.

⸻

3. Cloud Credential Dumping
	•	AWS / Azure / GCP metadata services abuse: extract temporary credentials.
	•	Credential files on endpoints (AWS CLI credentials, Azure auth tokens).
	•	OAuth tokens & browser credential stores (Chrome, Edge, Firefox).

⸻

🔹 Tools Commonly Used
	•	Mimikatz (Windows – plaintext, hashes, tickets).
	•	Impacket’s secretsdump.py (NTDS, SAM, LSASS).
	•	LaZagne (extracts passwords from apps/browsers).
	•	ProcDump (dump LSASS memory).
	•	Windows Credential Editor (WCE).
	•	Gsecdump.

⸻

🔹 Real-World Incidents Involving Credential Dumping
	1.	NotPetya (2017)
	•	Spread rapidly using stolen admin credentials after dumping from LSASS.
	•	Report: US-CERT Alert on NotPetya
	2.	SolarWinds / SUNBURST (2020)
	•	Attackers used credential dumping to escalate privileges and access Microsoft 365/Azure AD.
	•	Report: CISA Analysis Report
	3.	FIN7 (Carbanak Group)
	•	Extensively used Mimikatz to steal Windows credentials from retail and hospitality targets.
	•	Report: FireEye on FIN7
	4.	Equation Group (Linked to NSA leaks)
	•	Used DCSync attacks and LSASS dumping.
	•	Report: Wiki on Equation Group
	5.	APT29 (Cozy Bear)
	•	Used credential dumping in campaigns targeting COVID-19 vaccine research.
	•	Report: UK NCSC Advisory

⸻

🔹 Key References & Incident Reports
	•	MITRE ATT&CK: OS Credential Dumping
	•	Mimikatz GitHub
	•	FireEye on FIN7 Operations
	•	CISA SolarWinds Report
	•	US-CERT NotPetya Alert
	•	NCSC Advisory on APT29

⸻
