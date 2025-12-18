# Cybersecurity & Ethical Hacking Portfolio – George Ghira

This repository collects hands-on projects from my Udacity cybersecurity programs:

- **Introduction to Cybersecurity** (2023)  
- **Ethical Hacking / Offensive Security** (2024–2025)

Each project simulates a realistic scenario and includes the original reports, slides, and templates used for grading.

---

## Repository structure

- `intro-cybersecurity-2023/` – Blue-team focused projects  
  - `project-1-secure-business-pc/` – Hardening a small business Windows 10 PC for Joe’s Auto Body.  
  - `project-2-dfi-monitoring/` – Monitoring and securing the Douglas Financials Inc. (DFI) environment.  
  - `project-3-hospital-ransomware/` – Ransomware incident response for a group of hospitals.  
  - `project-4-swifttech-risk-assessment/` – Vendor risk assessment and security addendum for a cloud logging provider.

- `ethical-hacking-2024/` – Red-team / penetration testing projects  
  - `project-5-examplecorp-audit/` – End-to-end attack path against ExampleCorp (scanning → exploitation → post-exploitation).  
  - `project-6-pj-bank-penetration-test/` – Web application and infrastructure assessment for PJ Bank (currently in progress).

---

## Intro to Cybersecurity (2023)

### Project 1 – Securing a Small Business Windows 10 PC

**Folder:** `intro-cybersecurity-2023/project-1-secure-business-pc/`  

Joe runs a small auto body shop and uses a Windows 10 PC for all business operations. I performed a full host-level security review and hardening:

- Collected a full **asset inventory** (hardware, OS build, installed apps, services, and accounts).  
- Compared the actual configuration against **CIS Critical Security Controls** and Windows security baselines.  
- Hardened the system by enabling and tuning:
  - Windows Defender Firewall
  - Antivirus / malware protection
  - User Account Control (UAC)
  - Removable media / AutoPlay behavior
- Cleaned up user accounts and privileges according to **least privilege**.  
- Secured sensitive business files by:
  - Tightening NTFS permissions so only Joe and his assistant can modify them.
  - Encrypting work data into a password-protected archive for safe backup.

**Key skills:** Windows host hardening, CIS Controls mapping, baseline comparison, file encryption, basic forensics.

---

### Project 2 – Monitoring & Securing the DFI Environment

**Folder:** `intro-cybersecurity-2023/project-2-dfi-monitoring/`  

Douglas Financials Inc. (DFI) is growing and hiring its first dedicated InfoSec analyst. This project focuses on tightening a mixed Windows / Linux environment and improving monitoring:

- Reviewed Windows Server configuration for **permissions, services, and encryption** settings and proposed hardening steps.  
- Identified access control issues in departmental shares (HR, IT, Operations, Public) and recommended corrected ACLs.  
- Wrote a **Cisco ASA firewall rule** to allow a partner’s application traffic on a specific TCP port using named objects.  
- Designed **VPN encryption** using IPsec with AES and SHA-based integrity for a new payroll partner connection.  
- Created **Snort IDS rules** to detect:
  - Potential ICMP-based DDoS against a file server.
  - Suspicious TFTP access to a VoIP server.
- Verified file integrity with **hashing** and proposed log-based detection for RDP brute-force attempts.  
- Recommended **security automation** (SOAR, firewall automation, endpoint protection, backup and recovery) and summarized Windows update priorities.

**Key skills:** Windows/Linux hardening, ACL design, Cisco firewall rules, IDS signatures, hash verification, security automation proposals.

---

### Project 3 – Hospital Ransomware Incident & Response

**Folder:** `intro-cybersecurity-2023/project-3-hospital-ransomware/`  

Several hospitals are hit by a coordinated ransomware campaign that encrypts centralized logs and backups. I treated this as an incident response and analysis exercise:

- Built a **threat profile** for the ransomware campaign (FIN-style financially motivated actor, phishing entry point, exploitation of an unpatched Windows vulnerability).  
- Conducted a **vulnerability scan** against a target host and summarized findings by severity (critical/high/medium/low/info).  
- Ran a small **password cracking** exercise with Hashcat against MD5 password hashes to show weak password hygiene.  
- Completed a structured **incident response checklist**, including:
  - Incident classification and impact assessment.
  - Affected systems and business impact (especially patient care).
  - Recommended containment, eradication, and recovery steps.
- Proposed **lessons learned** and improvements in patch management, network segmentation, monitoring, and staff communication.

**Key skills:** Threat profiling, vulnerability management, password auditing, incident response planning, business-focused reporting.

---

### Project 4 – SwiftTech Risk Assessment & Security Addendum

**Folder:** `intro-cybersecurity-2023/project-4-swifttech-risk-assessment/`  

SwiftTech is a cloud logging provider going through a SOC-style review for a healthcare customer. I evaluated their posture and drafted a contractual security addendum:

- Analyzed SwiftTech’s **architecture and controls** (encryption, segmentation, VPN, patching, code scanning).  
- Built a **risk register** in Excel listing key risks, likelihood, impact, and remediation ideas.  
- Drafted an **information security addendum** for the Master Service Agreement, covering:
  - Information Security and Risk Management policies  
  - Encryption requirements (e.g., AES-256 at rest for customer data)  
  - Patch and vulnerability management expectations  
  - Secure SDLC and code-scanning expectations  
  - Access control and MFA requirements
- Presented findings in a **slide deck** aimed at non-technical stakeholders, mapping recommendations to frameworks such as HIPAA and the NIST Cybersecurity Framework.

**Key skills:** Vendor risk assessment, risk register design, security contract language, mapping to frameworks (HIPAA, NIST CSF, CIS), executive communication.

---

## Ethical Hacking & Offensive Security (2024–2025)

### Project 5 – ExampleCorp Vulnerability Assessment & Exploitation

**Folder:** `ethical-hacking-2024/project-5-examplecorp-audit/`  

This project walks through an end-to-end attack path against ExampleCorp using both automated scanning and manual exploitation:

- Ran a **Nessus vulnerability scan** with a custom policy (all ports, multiple plugin families) and reviewed the vulnerability dashboard and Apache CouchDB findings.  
- Analyzed CVEs **CVE-2017-12635** and **CVE-2017-12636** with CVSS v3.0 scores and discussed their impact on confidentiality, integrity, and availability.  
- Performed service discovery with **Nmap**, identifying key services and versions.  
- Chained together:
  - **OSINT** findings (firewall exceptions, file-upload references).  
  - **Phishing results** (harvested usernames and passwords).  
  - **Web vulnerabilities**:
    - Local File Inclusion (LFI) via a `?file=` parameter.  
    - Insecure file upload that allowed a `.php.jpg` web shell.  
  - A **reverse shell** via the backdoor, followed by system enumeration, process and network inspection.  
- Explored DNS misconfigurations on port 53 (zone transfer / AXFR) to identify internal infrastructure and potential avenues for lateral movement.  
- Tested additional services (FTP, WordPress endpoints) with tools like Hydra, wfuzz, and wpscan.

**Key skills:** Nessus scanning, CVSS analysis, CouchDB exploitation, OSINT, phishing analysis, LFI/file-upload exploitation, reverse shells, DNS zone-transfer abuse, brute-force tooling.

---

### Project 6 – PJ Bank Web Application & VM Assessment (in progress)

**Folder:** `ethical-hacking-2024/project-6-pj-bank-penetration-test/`  

This is a **draft** security report for PJ Bank’s custom virtual environment:

- Defines the **scope** (public web server, employee workstation, DMZ servers).  
- Documents **reconnaissance**:
  - DNS and WHOIS information for `learnaboutsecurity.com`.  
  - Cloudflare-backed hosting, nameservers, and lack of DNSSEC.  
  - Technologies used (React, Gatsby, Bootstrap, etc.).  
- Contains placeholders for:
  - Formal risk rating and recommendations.  
  - Significant vulnerabilities summary.  
  - Detailed scanning and exploitation sections.

**Key skills (so far):** OSINT, tech stack enumeration, report writing.  
**Status:** The report template is partially filled and kept to show methodology; I plan to complete the vulnerability and exploitation sections.

---

## Skills demonstrated across the repo

Across all projects, this portfolio shows experience in:

- **Blue team / defense**
  - Windows & Linux hardening
  - Firewall, VPN, and IDS/IPS rule design
  - Vulnerability management and patch recommendations
  - Incident response and ransomware playbooks
  - Vendor risk assessment and security governance

- **Red team / offensive**
  - Nmap and Nessus scanning
  - Exploiting misconfigurations (CouchDB, web apps, DNS)
  - Web exploitation: LFI, insecure file upload, reverse shells
  - Phishing result analysis and credential use in attacks

- **Governance, Risk & Compliance**
  - Working with CIS Controls, NIST CSF, HIPAA-aligned expectations
  - Building risk registers and security addenda for contracts
  - Communicating technical risk to non-technical stakeholders

---
