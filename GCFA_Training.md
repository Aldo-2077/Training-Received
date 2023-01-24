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

Memory forensics has become a crucial part of many advanced toolkits and essential for incident response and threat hunting teams. It can reveal evidence of worms, rootkits, PowerShell attacks, ransomware precursors, and advanced malware used by targeted attackers. 

Memory analysis is no longer just for Windows internals experts and reverse engineers, thanks to new tools, techniques, and detection methods. These advancements make memory analysis accessible to all investigators, incident responders, and threat hunters. Understanding attack patterns in memory is a key skill for analysts using endpoint detection and response (EDR) products, making these tools even more effective. 

This section explored some of the most powerful memory analysis capabilities and provided a solid foundation of advanced memory forensic skills to enhance investigations, regardless of the toolset used.

**Hands-on Exercises**
- Scaling remote endpoint incident response, hunting, and analysis using Velociraptor
- Remote endpoint triage and memory examination using F-Response Enterprise
- Creating local and remote triage evidentiary images with KAPE
- Detect unknown live and dormant custom malware in memory across multiple systems in an enterprise environment
- Examine Windows process trees to identify normal versus anomalies
- Find advanced "beacon" malware over common ports used by targeted attackers to access command and control (C2) channels
- Find residual attacker command-line activity through scanning strings in memory and by extracting command history buffers
- Compare compromised system memory against a baseline system using Frequency of Least Occurrence stacking techniques
- Identify advanced malware hiding techniques, including code injection and rootkits
- Employ indicators of compromise to automate analysis
- Analysis of memory from infected systems:
    - Stuxnet
    - TDL3/ TDSS
    - CozyDuke APT29 RAT
    - Rundll32 and Living Off the Land Executions
    - Zeus/Zbot/Zloader
    - Emotet
    - SolarMarker
    - Black Energy Rootkit
    - WMI and PowerShell
    - Cobalt Strike Beacons and Powerpick
    - Cobalt Strike Sacrificial Processes
    - Metasploit
    - Custom APT command and control malware
### **Topics**

**Remote and Enterprise Incident Response**

- Remote Endpoint Access in the Enterprise
- Remote Endpoint Host-based Analysis
- Scalable Host-based Analysis (one analyst examining 1,000 systems) and Data Stacking
- Remote Memory Analysis
- Velociraptor, F-Response, and KAPE

**Triage and Endpoint Detection and Response (EDR)**

- Endpoint Triage Collection
- EDR Capabilities and Challenges
- EDR and Memory Forensics

**Memory Acquisition**

- Acquisition of System Memory
- Hibernation and Pagefile Memory Extraction and Conversion
- Virtual Machine Memory Acquisition
- Memory changes in Windows 10 and 11

**Memory Forensics Analysis Process for Response and Hunting**

- Understanding Common Windows Services and Processes
- Identify Rogue Processes
- Analyze Process Objects
- Review Network Artifacts
- Look for Evidence of Code Injection
- Audit Drivers and Rootkit Detection
- Dump Suspicious Processes and Drivers

**Memory Forensics Examinations**

- Live Memory Forensics
- Memory Analysis with Volatility
- Webshell Detection Via Process Tree Analysis
- Code Injection, Malware, and Rootkit Hunting in Memory
- Advanced Memory Forensics with MemProcFS
- WMI and PowerShell Process Anomalies
- Extract Memory-Resident Adversary Command Lines
- Investigate Windows Services
- Hunting Malware Using Comparison Baseline Systems
- Find and Dump Cached Files from RAM

**Memory Analysis Tools**

- F-Response
- Velociraptor
- Volatility
- MemProcFS

---

## Timeline Analysis

**Overview**

I have gained expertise in advanced incident response and hunting techniques through hands-on training with the pioneers of timeline analysis. By utilizing temporal data found in various sources such as filesystems, log files, network data, registry data, and browser history, I am able to quickly and effectively analyze and solve cases. 

Developed by Rob Lee as early as 2001, timeline analysis has become a crucial tool in incident response, hunting, and forensics. With new frameworks and simultaneous examination capabilities, what once took days can now be completed in minutes. 

This training covered the methods for building and analyzing timelines, as well as key analysis techniques to effectively utilize them in cases.

**Hands-on Exercises**

- Detecting malware defense evasion techniques
- Using timeline analysis, track adversary activity by hunting an APT group's footprints of malware, lateral movement, and persistence
- Target hidden and time-stomped malware and utilities that advanced adversaries use to move in the network and maintain their presence
- Track advanced adversaries' actions second-by-second through in-depth super-timeline analysis
- Observe how attackers laterally move to other systems in the enterprise by watching a trail left in filesystem times, registry, event logs, shimcache, and other temporal-based artifacts
- Identify root cause of an intrusion
- Learn how to filter system artifact, file system, and registry timelines to target the most important data sources efficiently
### **Topics**

**Malware Defense Evasion and Detection**

- Indicators of Compromise - YARA
- Entropy and Packing Analysis
- Executable Anomaly Detection
- Digital Signature Analysis

**Timeline Analysis Overview**

- Timeline Benefits
- Prerequisite Knowledge
- Finding the Pivot Point
- Timeline Context Clues
- Timeline Analysis Process

**Filesystem Timeline Creation and Analysis**

- MACB Timestamps
- Windows Time Rules (File Copy versus File Move)
- Filesystem Timeline Creation Using Sleuthkit, fls and MFTECmd
- Bodyfile Analysis and Filtering Using the mactime Tool

**Super Timeline Creation and Analysis**

- Super Timeline Artifact Rules
- Program Execution, File Knowledge, File Opening, File Deletion
- Timeline Creation with log2timeline/Plaso
- log2timeline/ Plaso Components
- Filtering the Super Timeline Using psort
- Targeted Super Timeline Creation
- Super Timeline Analysis Techniques
- Scaling Super Timeline Analysis with Elastic Search (ELK)

---

## Advanced Adversary and Anti-Forensics Detection

**Overview**

Criminals and ransomware attackers often employ various techniques to conceal their presence on compromised systems, making it difficult for forensic professionals and incident responders to uncover critical evidence. However, by understanding various aspects of the operating system and file system, it is possible to recover files, file fragments, and metadata that can reveal important information such as deleted logs, attacker tools, and exfiltrated data. This can provide a deeper understanding of the attacker's tactics, techniques, and procedures (TTPs) and aid in quickly identifying and mitigating the damage caused by an intrusion. 

In some cases, these deep-dive techniques may be the only way to prove that an attacker was active on a system and determine the root cause of an incident. These methods are not only useful in intrusion cases, but can also be applied in nearly every forensic investigation.

**Hands-on Exercises**
    
- Volume shadow snapshot analysis
- Timelines incorporating volume shadow snapshot data
- Anti-Forensics analysis using NTFS filesystem components
- Timestomp identification and suspicious file detections
- Advanced data recovery with records carving and deleted volume shadow copy recovery
### **Topics**

**Volume Shadow Copy Analysis**

- Volume Shadow Copy Service
- Options for Accessing Historical Data in Volume Snapshots
- Accessing Shadow Copies with vshadowmount
- Volume Shadow Copy Timelining

**Advanced NTFS Filesystem Tactics**- 
- NTFS Filesystem Analysis
- Master File Table (MFT) Critical Areas
- NTFS System Files
- NTFS Metadata Attributes
- Rules of Windows Timestamps for $StdInfo and $Filename
- Detecting Timestamp Manipulation
- Resident versus Nonresident Files
- Alternate Data Streams
- NTFS Directory Attributes
- B-Tree Index Overview and Balancing
- Finding Wiped/Deleted Files using the $I30 indexes
- Filesystem Flight Recorders: $Logfile and $UsnJrnl
- Common Activity Patterns in the Journals
- Useful Filters and Searches in the Journals
- What Happens When Data Is Deleted from an NTFS Filesystem?

**Advanced Evidence Recovery**

- Markers of Common Wipers and Privacy Cleaners
- Deleted Registry Keys
- Detecting "Fileless" Malware in the Registry
- File Carving
- Volume Shadow Carving
- Carving for NTFS artifacts and Event Log Records
- Effective String Searching
- NTFS Configuration Changes to Combat Anti-Forensics
---

## The APT Threat Group Incident Response Challenge

**Overview**

This exercise immerses participants in a simulated advanced persistent threat (APT) attack, providing a realistic and engaging learning experience. Based on real-world scenarios, it incorporates techniques learned throughout the course and tests participants' newly acquired skills in investigating an enterprise intrusion. 

The exercise covers the entire process of uncovering compromised systems, identifying lateral movement and stolen intellectual property, and is led by instructors with extensive experience in defending against advanced threats from various threat actors.

### **Topics**

- The Intrusion Forensic Challenge asked each incident response team to analyze multiple systems in an enterprise network with many endpoints.

- Learned to identify and track attacker actions across an entire network finding initial exploitation, reconnaissance, persistence, credential dumping, lateral movement, elevation to domain administrator, and data theft/exfiltration.

- Witnessed and participated in a team-based approach to incident response.

- Discovered evidence of some of the most common and sophisticated attacks in the wild including Cobalt Strike, Metasploit, PowerShell exploit frameworks, and custom nation-state malware.

- During the challenge, each incident response team answered key questions and address critical issues in the different categories listed below, just as they would during a real breach in their organizations:

**IDENTIFICATION AND SCOPING:**

1. How and when was the network breached?

2. List all compromised systems by IP address and specific evidence of compromise.

3. When and how did the attackers first laterally move to each system?

**CONTAINMENT AND THREAT INTELLIGENCE GATHERING:**

4. How and when did the attackers obtain domain administrator credentials?

5. Once on other systems, what did the attackers look for on each system?

6. Find exfiltrated email from executive accounts and perform damage assessment.

7. Determine what was stolen: Recover any attacker archives, find encryption passwords, and extract the contents to verify exfiltrated data.

8. Collect and list all malware used in the attack.

9. Develop and present cyber threat intelligence based on host and network indicators of compromise.

**REMEDIATION AND RECOVERY:**

10. What level of account compromise occurred. Is a full password reset required during remediation?

11. Based on the attacker techniques and tools discovered during the incident, what are the recommended steps to remediate and recover from this incident?

    a. What systems need to be rebuilt?

    b. What IP addresses need to be blocked?

    c. What countermeasures should we deploy to slow or stop these attackers if they come back?

    d. What recommendations would you make to detect these intruders in our network again?