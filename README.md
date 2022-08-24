## Training-Received (document in process)
---

This repository encompasses training that I have received from:
- Courses completed at SANS, Arizona State University, and University of Phoenix.

- Self-study from:  CyberStart CTF Competition, TryHackMe, YT personalities, Udemy, Coursera, and from books.

---
<br>

*Click links for more detail.*

## Table of Training
[1.  SANS SEC504 Hacker Tools, Techniques, and Incident Handling (GCIH)](#sans-sec504-hacker-tools-techniques-and-incident-handling-gcih)
- [Incident Response and Cyber Investigation](#incident-response-and-cyber-investigations)

- [Recon, Scanning, and Enumeration Attacks](#recon-scanning-and-enumeration-attacks)
 
- [Password and Access Attacks](#password-and-access-attacks)

- [Public-Facing and Drive-By Attacks](#public-facing-and-drive-by-attacks)
 
- [Evasive and Post-Exploitation Attacks](#evasive-and-post-exploitation-attacks)

- [Capture the Flag Event](#capture-the-flag-event)

---
<br>

# SANS SEC504 Hacker Tools, Techniques, and Incident Handling (GCIH)
- ## Incident Response and Cyber Investigations
    **Overview**
    
    The first section of SEC504 focuses on how to develop and build an incident response process in your organization by applying the Dynamic Approach to Incident Response (DAIR) to effectively verify, scope, contain, assess, and remediate threats. We'll apply this process in-depth with hands-on labs and examples from real-world compromises.<br><br>

    **Hands-on Exercises**
    
    - Live Windows examination
    - Network investigation
    - Memory investigation
    - Malware investigation
    - Cloud investigation<br><br>
    
    ### **Topics**

    **Incident Response**

    - Case study: Argous Corporation compromise
    - Dynamic Approach to Incident Response
    - Investigative analysis: Examining incident evidence<br><br>
    
    **Digital Investigations**

    - Techniques for digital investigation
    - Establishing an incident timeline
    - Investigation efficiency: Data reduction<br><br>

    **Live Examination**

    - Using PowerShell for Windows threat hunting
    - Identifying suspicious Windows processes
    - Correlating network and persistence activity
    - Assessing file-less malware threats
    - Enumerating Windows auto-start extensibility points
    - Leveraging Sysinternals for live Windows examinations<br><br>

    **Network Investigations**

    - Identifying compromised host beaconing with proxy server logs
    - Filtering network activity to identify indicators of compromise
    - Assessing encrypted network traffic with multiple data sources
    - Building the incident timeline<br><br>

    **Memory Investigations**

    - Collecting volatile memory from a compromised host
    - Conducting offline analysis of attacker persistence
    - Using Volatility 3 to investigate malware
    - Build attacker event timelines using non-volatile memory captures<br><br>

    **Malware Investigations**

    - Assessing attacker malware in a safe test environment
    - Using snapshot and continuous recording tools
    - Inspecting malware actions with RegShot and Procmon
    - Identifying malicious code on Windows<br><br>

    **Cloud Investigations**

    - Steps for conducting a cloud security incident investigation
    - Essential cloud logging assets for incident response
    - Data collection and isolation for compromise assessment
    - Applying cloud recovery and remediation following an incident
    - Complete cloud compromise incident response walkthrough<br><br>

    **Bootcamp: Linux Olympics**

    - Learn Linux using an interactive learning environment
    - Build command line skills
    - Working with Linux file systems and permissions
    - Using JQ to parse and filter JSON data
    - Using file parsing tools, including grep, cut, and awk
    - Linux compromise incident response walkthrough<br><br>

    **Bootcamp: PowerShell Olympics**

    - Learn PowerShell on Windows using an interactive learning environment
    - Build command line skills
    - PowerShell skills: cmdlets, functions, built-ins, and more!
    - Learned to quickly interrogate a Windows system for effective threat hunting
    - Accelerate common analysis tasks with PowerShell automation<br>

    ---
    <br>

    ## Recon, Scanning, and Enumeration Attacks
    **Overview**

        In this course section I learned about the techniques attackers use to conduct reconnaissance as a pre-attack step, including how they use open-source intelligence, network scanning, and target enumeration attacks to find the gaps in your network security. You'll use attacker techniques to assess the security of a target network, evaluating popular protocols and endpoints for Windows, Linux, and cloud targets. After delivering the attacks, you'll investigate the logging data and evidence that remains to recognize these attacks as they happen.
        
    **Hands-on Exercises**

    - Open-Source Intelligence with SpiderFoot
    - DNS Reconnaissance and Enumeration
    - Host Discovery and Assessment with Nmap
    - Shadow Cloud Asset Discovery with Masscan
    - Windows Server Message Block (SMB) Session Attacks
    - Windows Password Spray Attack Detection<br><br>

    ### **Topics**

    **MITRE ATT&CK Framework Introduction**

    - Using ATT&CK to guide an incident response investigation
    - Staying current with changing attack techniques
    - Leveraging ATT&CK for threat intelligence<br><br>

    **Open-Source Intelligence**

    - Enumerating targets without being detected
    - Host identification through domain and public certificate authority data
    - User account compromise assessment
    - Automating open-source intelligence collection with SpiderFoot<br><br>

    **DNS Interrogation**

    - Mining public DNS servers for organization data
    - Automating host enumeration with dns-brute
    - DNS server log inspection for attack identification
    - Creative host identification using manual and automated tools<br><br>

    **Website Reconnaissance**

    - Information-gathering from public websites
    - Parsing Exchangeable Image File Format (EXIF) data from public documents
    - Optimizing search engine reconnaissance interrogation
    - Abstracting attack identification using public sources
    - Limiting website-sensitive data disclosure<br><br>

    **Network and Host Scanning with Nmap**

    - Host enumeration and discovery with Nmap
    - Internal and external network mapping and visualization
    - Minimizing network activity to avoid detection
    - Deep host assessment with Nmap Scripting Engine tools<br><br>

    **Cloud Spotlight: Cloud Scanning**

    - Enumerating shadow cloud targets
    - Accelerating scans with Masscan
    - Walkthrough: Scanning Amazon Web Services for target discovery
    - Attributing cloud hosts to a target organization
    - Visual representation of identified targets with EyeWitness<br><br>

    **Server Message Block (SMB) Sessions**

    - Understanding Windows SMB: Essential skill development
    - Identifying SMB attacks against Windows
    - Using built-in tools for SMB password guessing attacks
    - Understanding SMB security features
    - Identifying sensitive data loss from SMB file server shares<br><br>

    **Defense Spotlight: DeepBlueCLI**

    - Identifying attacks using Windows Event Logs
    - Differentiating attacks from false positives
    - Remote host assessment for compromise identification
    - Tips for fast assessment to begin incident analysis<br><br>


    ---
    <br>

    ## Password and Access Attacks
    **Overview**

    Password attacks are the most reliable mechanism for attackers to bypass defenses and gain access to your organization's assets. In this course section we investigated the complex attacks that exploit password and multi-factor authentication weaknesses using the access gained to access other network targets.

    
    **Hands-on Exercises**

    - Local password Guessing Attacks with Hydra
    - Cloud Password Guessing Attacks against Microsoft 365 using AWS Services
    - Password Cracking with John the Ripper
    - Password Cracking with Hashcat
    - Cloud Bucket Discovery
    - The Many Uses of Netcat<br><br>

    ### **Topics**

    **Password Attacks**

    - Password attack trifecta: Guessing, spray, and credential stuffing
    - Techniques for bypassing password attack defenses
    - Understanding real-world authentication attacks<br><br>

    **Microsoft 365 Attacks**

    - Enumerating valid Microsoft 365 user accounts
    - Assessing and bypassing Multi-Factor Authentication (MFA)
    - Attacking cloud Software as a Service (SaaS) platforms
    - Leveraging AWS services to bypass account lockout
    - Differentiating Microsoft Gov Cloud and enterprise cloud security<br><br>

    **Understanding Password Hashes**

    - Weaknesses in Windows password hash formats
    - Collecting password hashes in Windows, Linux, and cloud targets
    - Mitigating GPU-based password cracking with scrypt and Argon2<br><br>

    **Password Cracking**

    - Recovering passwords from hashes with John the Ripper and Hashcat
    - Accelerating password cracking with GPUs and cloud assets
    - Effective cracking with password policy masks
    - Multi-factor authentication and password cracking implications<br><br>

    **Cloud Spotlight: Insecure Storage**

    - Case study: Cloud bucket storage exposure
    - Understanding cloud storage for Amazon Web Services, Azure, and Google Compute
    - Discovering insecure bucket storage
    - Walkthrough: Insecure storage to website persistence compromise
    - Identifying insecure cloud storage access<br><br>

    **Multi-purpose Netcat**

    - Internal data transfer to evade monitoring controls
    - Pivoting and lateral movement
    - Listener and reverse TCP backdoors on Linux and Windows
    - Detailed look at attacker post-compromise techniques
    - Living Off the Land (LOL) attacks to evade endpoint detection tools<br><br>

    ---
    <br>
    
    ## Public-Facing and Drive-By Attacks
    **Overview**

    In this course section we looked at target exploitation frameworks that take advantage of weaknesses on public servers and client-side vulnerabilities. Using the implicit trust of a public website, we applied attacker tools and techniques to exploit browser vulnerabilities, execute code with Microsoft Office documents, and exploit the many vulnerabilities associated with vulnerable web applications.<br><br>

    **Hands-on Exercises**

    - Metasploit Attack and Analysis
    - Client-side Exploitation with the Browser Exploitation Framework (BeEF)
    - Windows System Resource Usage Database Analysis
    - Command Injection Attack
    - Cross-Site Scripting Attack
    - SQL Injection Attack
    - Server Side Request Forgery (SSRF) and Instance Metadata Service (IMDS) Attack<br><br>

    ### **Topics**

    **Metasploit Framework**

    - Using Metasploit to identify, configure, and deliver exploits
    - Selecting payloads that grant access while evading defenses
    - Establishing and using Command & Control (C2) victim access
    - Identifying Metasploit and Meterpreter fingerprints for incident response<br><br>

    **Drive-By Attacks**

    - Phishing and malicious Microsoft Office files
    - Leveraging a watering hole to attack victim browsers
    - Case study: Control system attack through watering hole forum compromise
    - Building extensible payloads for effective attacks
    - Customizing exploits for defense bypass<br><br>

    **Defense Spotlight: System Resource Usage Monitor**

    - Leveraging Windows diagnostics for incident response
    - Assessing incident network activity using built-in Windows data
    - Case study: Data theft and terminated employee workstation analysis<br><br>

    **Command Injection**

    - Compromising websites with command injection
    - Walkthrough: Falsimentis community service website attack
    - Applying command injection in non-website targets
    - Attack access enumeration through command injection
    - Auditing web applications for command injection flaws<br><br>

    **Cross-Site Scripting (XSS)**

    - Exploiting victim browsers through server flaws
    - Classifying XSS types for opportunistic or target attacks
    - Cookie theft, password harvesting, and camera/microphone capture attacks
    - Using content security policies (CSP) to stop XSS<br><br>

    **SQL Injection**

    - Understanding SQL constructs and developer errors
    - Extracting data through SQL injection
    - Using Sqlmap to automate vulnerability discovery
    - SQL injection against cloud databases: Relational Database Service (RDS), Spanner, Azure SQL<br><br>

    **Cloud Spotlight: SSRF and IMDS Attacks**

    - Identifying server-side request forgery vulnerabilities
    - Understanding common requests vs. server-side requests
    - Walkthrough: Falsimentis federated SSO attack
    - Obtaining cloud keys through IMDS attacks<br><br>

    ---
    <br>

    ## Evasive and Post-Exploitation Attacks
    **Overview**

    Building on password, public-facing, and drive-by attacks, we looked at the attacks that happen after initial exploitation.  I learned how attackers bypass endpoint protection systems and use an initial foothold to gain access to internal network targets. Then we applied the techniques learned with privileged insider LAN attacks, using privileged access to establish persistence, and how attackers scan for and collect data from a compromised organization. We applied these skills to assess the security risks of a vulnerable cloud deployment through visualization and automated assessment techniques.  Finally, we'll look at the steps to take after the course is over, turning what you've learned into long-term skills and helping you prepare for the certification exam.<br><br>
    
    **Hands-on Exercises**

    - Endpoint Protection Bypass: Bypassing Application Allow Lists
    - Pivoting and Lateral Movement with Metasploit
    - Insider Attack with Responder
    - Establishing Persistence with Metasploit
    - Network Threat Hunting with Real Intelligence Threat Analytics (RITA)
    - Cloud Configuration Assessment with ScoutSuite<br><br>

    ### **Topics**

    **Endpoint Security Bypass**

    - Understanding the three techniques for endpoint bypass
    - Evading application safelist controls
    - Using signed executables to evade endpoint controls
    - Using Microsoft-signed tools to attack systems: Living Off the Land (LOL)
    - Getting the most value from Endpoint Detection and Response (EDR/XDR) platforms<br><br>

    **Pivoting and Lateral Movement**

    - Using Metasploit features for lateral movement
    - Attacker detection evasion through pivoting
    - Using Linux and Windows features for advanced exploitation
    - Command & Control (C2) for privileged internal access<br><br>

    **Hijacking Attacks**

    - Exploiting privileged LAN access
    - Attacking default Windows vulnerable protocols
    - Password harvesting on the LAN<br><br>

    **Covering Tracks**

    - Hiding collected data on Windows and Linux
    - Log editing techniques for both simple and complex log formats
    - Building tamper-proof logging platforms<br><br>

    **Establishing Persistence**

    - Windows Management Instrumentation (WMI) Event Subscription persistence techniques
    - Exploiting Windows Active Directory: Golden Ticket attacks
    - Web shell access and multi-platform persistence
    - Cloud keys and backdoor accounts in Azure, Amazon Web Services, and Google Compute<br><br>

    **Defense Spotlight: Real Intelligence Threat Analytics**

    - Threat hunting through network analysis
    - Identifying beacons and C2 on your network
    - Characterizing network oddities: Long connections
    - Catching DNS exfiltration and access attacks<br><br>

    **Data Collection**

    - Linux and Windows post-exploitation password harvesting
    - Evading detection controls: Mimikatz
    - Attacking password managers on Windows and macOS<br><br>

    **Cloud Spotlight: Cloud Post-Exploitation**

    - Privilege enumeration and escalation in cloud environments
    - Identifying stealthy backdoors in Azure
    - Using cloud attack frameworks: Pacu and GCP PrivEsc
    - Case study: Access to database dumping in Google Compute
    - Built-in tools for data access: Microsoft 365 Compliance Search
    - Assessing your cloud deployment for vulnerabilities<br><br>
    ---
    <br>

    ## Capture the Flag Event
    **Overview**

    This event is full week of hands-on activity that has you working as a consultant for ISS Playlist, a fictitious company that has recently been compromised. We utilized the skills learned in class, using the same techniques used by attackers to compromise modern, sophisticated network environments. Practicing to scan, exploit, and complete post-exploitation tasks against a cyber range of target systems including Windows, Linux, Internet of Things devices, and cloud targets. This hands-on challenge is designed to help players practice their skills and reinforce concepts learned throughout the course.  The event guides you through the steps to successfully compromise target systems, bypass endpoint protection platforms, pivot to internal network high-value hosts, and exfiltrate company data.<br><br>
    
    **Topics**

    - Target Discovery and Enumeration
    - Applying Open-Source Intelligence and Reconnaissance & Information-Gathering
    - Public-Facing Asset Compromise
    - Email Compromise
    - Attacking Windows Active Directory
    - Password Spray, Guessing, and Credential Stuffing Attacks
    - Post-Exploitation Pivoting and Lateral Movement
    - Choosing, Configuring, and Delivering Exploits
    - Internal Attacker Compromise Attribution


