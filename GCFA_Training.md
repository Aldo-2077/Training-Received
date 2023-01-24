# SANS FOR508 Advanced Incident Response, Threat Hunting, and Digital Forensics (GCFA)

## Topics
- [Advanced Incident Response and Threat Hunting](#advanced-incident-response-and-threat-hunting)

- [Intrusion Analysis](#intrusion-analysis)
 
- [Memory Forensics in Incident Response & Threat Hunting](#memory-forensics-in-incident-response--threat-hunting)

- [Timeline Analysis](#timeline-analysis)
 
- [Advanced Adversary and Anti-Forensics Detection](#advanced-adversary-and-anti-forensics-detection)

- [The APT Threat Group Incident Response Challenge](#the-apt-threat-group-incident-response-challenge)

---

## Advanced Incident Response and Threat Hunting

**Overview**

Attacks are a major concern in cybersecurity and it is essential to have a solid understanding of them in order to detect and prevent them effectively. During my training, I began by studying common attacker techniques and familiarizing myself with the characteristics of malware and other types of attacks. I also delved deeper into the methods that adversaries use to establish persistence in a network.

Persistence is a critical aspect of an attack and it is usually established early on. I learned how to hunt for potential threats in a network and identify them quickly. I also received practice in identifying and dealing with specific types of attacks such as those that use "living off the land" binaries, PowerShell, and WMI. These have become common methods used by advanced adversaries and it is important to be able to detect them at scale.

Finally, this section ended with a comprehensive discussion of Microsoft credentials, which are a major vulnerability in modern networks. Credentials are a prime target for attackers and I learned how to prevent, detect, and mitigate attacks on them. The complexity of credentials in the modern enterprise cannot be overstated and understanding the tools and techniques being used to target them is crucial to securing a network.

**Hands-on Exercises**

- Forensic Lab Setup and Orientation Using the SIFT Workstation
- Malware Persistence Detection and Analysis
- Scaling Data Collection and Analysis Across the Enterprises
- Finding and Analyzing Malicious WMI attacks
### **Topics**

**Real Incident Response Tactics**

- Preparation: Key tools, techniques, and procedures that an incident response team needs to respond properly to intrusions

- Identification/Scoping: Proper scoping of an incident and detecting all compromised systems in the enterprise

- Containment/Intelligence Development: Restricting access, monitoring, and learning about the adversary in order to develop threat intelligence

- Eradication/Remediation: Determining and executing key steps that must be taken to help stop the current incident and the move to real-time remediation

- Recovery: Recording of the threat intelligence to be used in the event of a similar adversary returning to the enterprise

- Avoiding "Whack-A-Mole" Incident Response: Going beyond immediate eradication without proper incident scoping/containment

**Threat Hunting**

- Hunting versus Reactive Response
- Intelligence-Driven Incident Response
- Building a Continuous Incident Response/Threat Hunting Capability
- Forensic Analysis versus Threat Hunting Across Endpoints
- Threat Hunt Team Roles
- ATT&CK - MITRE's Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK(TM))

**Threat Hunting in the Enterprise**

- Identification of Compromised Systems
- Finding Active and Dormant Malware
- Digitally Signed Malware
- Malware Characteristics
- Common Hiding and Persistence Mechanisms
- Finding Evil by Understanding Normal

**Incident Response and Hunting across Endpoints**

- WMIC & PowerShell
- PowerShell Remoting Scalability
- PowerShell Remoting Credential Safeguards
- Kansa PowerShell Remoting IR Framework

**Malware Defense Evasion and Identification**

- Service Hijacking/Replacement
- Frequent Compilation
- Binary Padding
- Packing/Armoring
- Dormant Malware
- Signing Code with Valid Certificates
- Anti-Forensics/Timestomping
- Living of the Land Binaries and Security Tool Evasion

**Malware Persistence Identification**

- AutoStart Locations, RunKeys
- Service Creation/Replacement
- Service Failure Recovery
- Scheduled Tasks
- DLL Hijacking Attacks
- WMI Event Consumers

**Prevention, detection, and mitigation of Credential Theft**

- Pass the Hash
- Credential Attacks with Mimikatz
- Token Stealing
- Cached Credentials
- LSA Secrets
- Kerberos Attacks
- Golden Tickets
- Kerberoasting
- DCSync
- NTDS.DIT theft
- Bloodhound and Active Directory Graphing
- Common dumping tools including Metasploit, Acehash, Windows Credential Editor, and many others.

---

## Intrusion Analysis

**Overview**

Cyber defenders have a wide range of tools and techniques at their disposal to detect, hunt, and track malicious activity within a network. Each step taken by an attacker leaves behind a unique artifact, and understanding these footprints is crucial for both red and blue teams.

Attacks tend to follow a predictable pattern, and by focusing on the immutable elements of this pattern, it becomes easier to identify malicious activity. For example, attackers will inevitably need to run code in order to achieve their objectives, and this can be detected through the use of application execution artifacts. Additionally, attackers will require one or more accounts to run this code, making account auditing a powerful means of identifying malicious activity. Furthermore, attackers will need a way to move throughout the network, so we look for artifacts left by the relatively small number of ways there are to accomplish internal lateral movement.

In this section, we cover common attacker tactics and discuss the various data sources and forensic tools that can be used to identify malicious activity within an enterprise.

**Hands-on Exercises**

- Hunting and Detecting Evidence of Execution at Scale with Prefetch, Shimcache and Amcache
- Discovering Credential abuse with Event Log Collection and Analysis
- Tracking Lateral Movement with Event Log Analysis
- Hunting Malicious use of WMI and PowerShell
### **Topics**

**Stealing and Utilization of Legitimate Credentials**

- Pass the Hash
- Single Sign On (SSO) Dumping using Mimikatz
- Token Stealing
- Cached Credentials
- LSA Secrets
- Kerberos Attacks
- NTDS.DIT theft

**Advanced Evidence of Execution Detection**

- Attacker Tactics, Techniques, and Procedures (TTPs) - Observed Via Process Execution
- Prefetch Analysis
- Application Compatibility Cache (ShimCache)
- Amcache Registry Examination
- Scaling ShimCache and Amcache Investigations

**Lateral Movement Adversary Tactics, Techniques, and Procedures (TTPs)**

- Compromising Credentials Techniques
- Remote Desktop Services Misuse
- Windows Admin Share Abuse
- PsExec and Cobalt Strike Beacon PsExec Activity
- Windows Remote Management Tool Techniques
- PowerShell Remoting/WMIC Hacking
- Cobalt Strike Lateral Movement and Credential Use
- Vulnerability Exploitation

**Log Analysis for Incident Responders and Hunters**

- Profiling Account Usage and Logons
- Tracking and Hunting Lateral Movement
- Identifying Suspicious Services
- Detecting Rogue Application Installation
- Finding Malware Execution and Process Tracking
- Capturing Command Lines and Scripts
- Anti-Forensics and Event Log Clearing

**Investigating WMI and PowerShell-Based Attacks**

- WMI Overview
- WMI Attacks Across the Kill Chain
- Auditing the WMI Repository
- WMI File System and Registry Residue
- Command-Line Analysis and WMI Activity Logging
- PowerShell Transcript and ScriptBlock Logging
- Discovering Cobalt Strike beacon PowerShell Import Activity
- Detecting PowerShell Injection from Cobalt Strike, Metasploit, and Empire
- PowerShell Script Obfuscation
---

## Memory Forensics in Incident Response & Threat Hunting

**Overview**

**Hands-on Exercises**

### **Topics**

---

## Timeline Analysis

**Overview**

**Hands-on Exercises**

### **Topics**

---

## Advanced Adversary and Anti-Forensics Detection

**Overview**

**Hands-on Exercises**

### **Topics**

---

## The APT Threat Group Incident Response Challenge

**Overview**

**Hands-on Exercises**

### **Topics**
