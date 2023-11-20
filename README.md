# Splunk SIEM Project

## Overview

This project aims to enhance the security of your domain environment using Splunk, a powerful SIEM (Security Information and Event Management) tool. By monitoring key events and behaviors, you can proactively identify and respond to potential security threats. The project covers various aspects, including Ransomware/Malware detection, Brute Force Attack detection, Network and Port Scanning Detection, Unencrypted Web communication, Memory Utilization Monitoring, Failed Password Attempts Monitoring, and Blocked URLs Monitoring.

## Lab Setup

### Environment:

#### Host VM: Domain Controller and Active Directory (Server 2019).
- Roles: Configured as the primary domain controller, responsible for managing the Active Directory Environment and also the Splunk Web Server.
#### Client VM: Windows 10, acting as a normal user.
- Roles: Configured to simulate a standard user machine within an organization, and installed Splunk Universal Forwarder on this VM.

## Lab Setup Steps

### Step 1: Virtual Machine Creation

**1. Create a VM on VirtualBox using the Server 2019 ISO.**

**2. Configure the network by adding a second adapter attached to an Internal Network, assigning it an IP address.**
### Step 2: Active Directory and Domain Controller Setup

**1. Install AD and create a domain, completing the deployment configuration by adding a new forest.**

**2. Create a dedicated domain admin account during the setup.**

### Step 3: Routing and NAT Configuration

**1. Configure RAS/NAT via the Server Manager on the admin profile.**

**2. Add Routing as a role service and enable NAT on the Routing and Remote Access Server Setup Wizard.**
### Step 4: DHCP Server Setup

**1. Set up a DHCP server on the domain controller to allow Windows 10 clients to get IP addresses for internet access.**

**2. Use the internal NIC as the default gateway (router).**

### Step 6: Windows 10 Client Configuration

**1. Create a new VM with Windows 10 ISO, attaching the network adapter to the Internal Network.**

**2. Select Windows 10 Pro to connect to the domain.**

## Table of Contents

1. [Installation and Configuration](#installation-and-configuration)
2. [Ransomware/Malware Detection](#ransomwaremalware-detection)
3. [Brute Force Attack Detection](#brute-force-attack-detection)
4. [Network and Port Scanning](#network-and-port-scanning)
5. [Unencrypted Web Communications](#unencrypted-web-communications)
6. [Memory Utilization Monitoring](#memory-utilization-monitoring)
7. [Failed Password Attempts Monitoring](#failed-password-attempts-monitoring)
8. [Blocked URLs Monitoring](#blocked-urls-monitoring)
9. [Prevention Measures for Enhanced Security](#prevention-measures-for-enhanced-security)
10. [Conclusion](#conclusion)

    
## <a name="installation-and-configuration"></a>Installation and Configuration




### 1. Setting Up Splunk Forwarder on Client VM

**- Download and install Splunk Forwarder on the client VM.**

<img width="500" alt="5 clientvm forwarder setup" src="https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/5786edd4-5396-4613-ad56-9e6a88926beb">

**- On the host VM, configure the receiving data to listen on port 9997.**

<img width="500" alt="3 port saved" src="https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/15977abb-8c4e-404d-b4e4-9affd416f237">

**- Create a new index named "clientvm" to organize security-related events.**

<img width="500" alt="6 new index" src="https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/ef324f0b-c660-4ef6-bc2e-d95c5bec6e2e">


### 2. Configuring Splunk Forwarder

**- Ensure that the outputs config has the host IP address.**

<img width="500" alt="10 outputs conf" src="https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/73c4334f-7217-4244-9038-ab3538deed33">

**- Configure the Splunk Web Server to allow traffic on port 9997, and also configure the Outbound Firewall Rules on the Client VM, and the Inbound Firewall Rules on the Host VM to allow port 9997.**

<img width="500" alt="11 firewall" src="https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/99eb8814-f15f-4fa8-9f88-2ce5734c2bae">

**- Restart the Splunk Forwarder for the effects to take place.**

## Ransomware/Malware Detection <a name="ransomwaremalware-detection"></a>

### Purpose
Ransomware operates by rapidly encrypting files, rendering them inaccessible until a ransom is paid. Detection is crucial to prevent data loss and financial consequences. The provided query, when transformed into an alert, monitors the rapid creation of files—an indicative behavior of ransomware. By setting up this alert, the system promptly notifies administrators when suspicious file creation patterns are detected, enabling swift action to contain and mitigate potential ransomware attacks.

### Steps

1. **Install and Configure Sysmon**
   - Download and install Sysmon on the client VM.
   - Configure Sysmon according to the desired settings. Utilize a configuration file tailored to capture relevant events for ransomware detection.

![25 sysmon config and install](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/dc2a9dde-383c-4998-bfaf-cbcfc240fff6)

2. **Test Sysmon by Viewing Event Viewer**
   - Validate Sysmon's functionality by creating a fake .exe file on the client VM.
   - Open the Event Viewer to confirm that Sysmon logs the relevant events, including the creation of the fake .exe file.

![26 sysmon malicious file](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/96f2a733-0cd1-4114-ad72-875195751c2e)

3. **Integrate Sysmon into input.conf on the Client VM**
   - Update the input.conf file on the Splunk host VM to include Sysmon logs. This allows Splunk to index and analyze Sysmon events.

![27 sysmon input](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/6e5de75e-ec42-4b40-a58b-6a76b42618a6)

4. **View Sysmon on Splunk**
   - Ensure Sysmon logs are successfully ingested into Splunk.
   - Create and run queries in Splunk to verify that Sysmon events are searchable and accessible.

![28 splunk sysmon](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/0905d962-07a6-478a-80d6-5a3f92a359d6)

![28 sysmon file](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/435c53fb-7802-44cd-8928-2c1d6a8162e7)

5. **Configure Ransomware Alert on Splunk**
   - Develop a Splunk query to detect patterns indicative of ransomware behavior, such as rapid file creation.
   - Transform the query into an alert in Splunk, specifying conditions that trigger the alert when suspicious activities are detected.

![29 ransomware alert](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/5287bf2c-464b-4cd1-9638-4ceeafbd7602)

6. **Splunk Log Showing Virus Download**
   - Extend the Splunk query to include detection of potential virus downloads or malicious file transfers.
   - Create an alert to notify administrators when a virus download pattern is identified through Splunk logs.

![29 splunk virus download](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/c217c029-476d-4ebf-ab35-f20cb6420b28)

7. **Check Registry Logs on Splunk**
   - Develop a Splunk query to monitor registry changes, specifically focusing on entries related to programs attempting to run at startup.
   - Set up an alert to inform administrators of any suspicious registry modifications, which may indicate malware attempting to establish persistence.

![30 registery run](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/25b25304-b265-4d65-b628-a4104fed9906)

![31 registery alert](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/95d6a427-3c66-4e16-b8b0-ce568add00eb)

**These steps collectively establish a robust ransomware/malware detection mechanism using Sysmon and Splunk, providing administrators with timely alerts and insights into potential security threats.**

## Brute Force Attack Detection <a name="brute-force-attack-detection"></a>

### Purpose

- A brute-force attack is a trial-and-error method where attackers systematically attempt various username and password combinations to gain unauthorized access. This method exploits weak or easily guessable credentials, relying on the sheer volume of attempts rather than specific knowledge about the target. Automated tools are utilized for this process. To identify potential brute-force attacks, the provided Splunk query analyzes Windows security logs, highlighting users who have experienced both successful logins and numerous failed attempts. Adjusting thresholds aligns the detection with specific security policies and environment characteristics.

### Steps

**1. Use the provided Splunk query to identify potential brute-force attacks.**

![34 BRUTEFORCE](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/45f66ebf-865f-42bd-a2f6-41e3bb10879d)

**2. Adjust thresholds based on security policies and environment characteristics. (For this example, we used 5 as a threshold)**

### Query

```spl
index=* sourcetype=win*security user=* user!="" 
| stats count(eval(action="success")) as successes count(eval("failure")) as failures by user 
| where successes>0 AND failures>5
```

## Network and Port Scanning <a name="network-and-port-scanning"></a>

### Purpose 

- Scanning is a method employed by attackers to explore available IPs and Ports across a network, revealing potential vulnerabilities for exploitation. While authorized personnel may conduct such activities for vulnerability assessment, it's crucial to be vigilant if unauthorized scanning occurs. The query identifies hosts reaching out to more than 500 IPs or ports rapidly, indicating potential scanning. The presence of a source IP suggests internal origin, signaling a possible infection, warranting prompt incident response.

![31 port scanning](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/4a92178a-688c-4892-a743-4a2e764aa0cb)

### Query

```spl
index=* sourcetype=firewall*
| stats dc(dest_port) as num_dest_port dc(dest_ip) as num_dest_ip by src_ip
| where num_dest_port > 500 OR num_dest_ip > 500
```

## Unencrypted Web Communications <a name="unencrypted-web-communications"></a>

### Purpose

- Secure communication is essential for protecting sensitive data. Unencrypted web communications pose a significant security risk. The query identifies instances of unencrypted communication, offering the flexibility to create dashboards for daily monitoring, generate periodic reports, or set up alerts for immediate notification. This proactive approach helps maintain a secure network environment, ensuring that critical resources are accessed only through encrypted connections.

![32 detecting unecrpted](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/c81a50c3-f562-4fee-86d1-a090727d427b)

### Query

```spl
index=* sourcetype=firewall_data dest_port!=443
| table _time user app bytes* src_ip dest_ip dest_port
```

## Memory Utilization Monitoring <a name="memory-utilization-monitoring"></a>

### Purpose:

- As the system's physical memory depletes, it resorts to storing data on disk, significantly slowing down data retrieval. To prevent performance issues, it's essential to track the memory utilization of OS processes. This is achieved by installing the Splunk add-on, enabling vmstat.sh, and setting up an alert to monitor memory usage. The query, scheduled at intervals, calculates the maximum memory utilization percentage by host. Alerts triggered when this surpasses 80% enable proactive identification of hosts at risk, facilitating timely intervention and system optimization.

### Steps:

1. **Install the [Splunk add-on](https://splunkbase.splunk.com/app/742).**


2. Ensure **vmstat.sh** is **enabled**.

<img width="500" alt="Screenshot 2023-11-20 201237" src="https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/a6c48b44-4e87-4d41-a23a-8ad1d76c8cc0">

**3. Set up an alert to monitor memory usage with the provided query.**

![33 memory](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/9993506e-6cb0-4f6e-9b94-44feef31d6d9)

### Query

```spl
index=main sourcetype=vmstat
| stats max(memUsedPct) as memused by host
| where memused > 80
```

## Failed Password Attempts Monitoring <a name="failed-password-attempts-monitoring"></a>

### Purpose
- Monitoring failed passwords is critical for identifying potential security breaches. A surge in failed login attempts indicates unauthorized access attempts. The Splunk query counts failed password attempts, offering insights into potential malicious activities. This information can be transformed into alerts, providing real-time notifications when a threshold of failed attempts is reached. Proactive monitoring of failed passwords strengthens overall cybersecurity, enabling timely responses to potential threats.

### Steps

**1. Create a dashboard that monitors EventCode 4625 in the index chosen.**

![15 - final dashboard](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/e19f3438-abe3-4940-9723-9fbba0b36580)

**2. Highlight important information for easy understanding.**

![16 - final final dashboard](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/1ea2e714-40fd-4b99-b611-37509924e810)

**3. In terms of setting an alert of when the user/host has more than 5 password attempts, the following query can be used to set an alert, in order to alert us of when that happens.**

![24 brute force](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/f4afb8d2-50a8-491d-afe8-5dd60f5d1cde)

### Query

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625 host=* host!=""
| stats count(eval(status="Success")) as successes count(eval(status="Failure")) as failures by host
| where successes>0 AND failures>5
```

## Blocked URLs Monitoring <a name="blocked-urls-monitoring"></a>

### Purpose:

- In a secure network environment, it's crucial to control and monitor user access to specific websites for compliance and security reasons. The implementation of a Group Policy Object (GPO) named 'Blocked URLs' on the Domain Controller facilitates the blocking of selected websites, such as Facebook and Instagram. By creating an outbound firewall rule, enforcing the policy, and integrating DNS debug logs into Splunk, administrators gain visibility into users attempting to access blocked URLs. The associated dashboard displays relevant details, empowering administrators to enforce internet usage policies effectively.

### Steps:

1. **Create a New GPO Named 'Blocked URLs'**
   - On the Domain Controller (Host VM), create a new Group Policy Object named 'Blocked URLs.'

![17 - new gpo](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/20f174c4-5d65-42b4-9cff-2c90bf0ec108)

2. **Create Outbound Firewall Rule to Block URLs**
   - Within the 'Blocked URLs' GPO, configure a new outbound firewall rule to block the IP addresses associated with specific websites (e.g., Facebook and Instagram). Obtain these IP addresses by pinging the websites from the command line.

![18 - firewall url](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/ae3b2ceb-67ab-4f65-9e04-1b5d65fa3297)


3. **Enforce GPO and Update Group Policy**
   - Execute `gpupdate/force` on the Domain Controller to enforce the newly created GPO and ensure it takes effect on the network.

![19 gpo updated](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/ebd0994e-a58c-4f4d-9277-d7936e26f3db)

4. **Check Blocked URL Access**
   - Verify the effectiveness of the GPO by attempting to access the blocked URLs from a client machine. Ensure that access attempts are blocked as intended.

![22 - url not working](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/3f2d3263-0b32-4a93-a3ba-c20106a25c35)

5. **Enable DNS Debug Logs and Send to Splunk**
   - Configure DNS debug logging on the Domain Controller to capture detailed information about DNS queries, including attempts to access blocked URLs.
   - Ensure that DNS debug logs are forwarded to Splunk for centralized monitoring and analysis.

6. **Create Splunk Dashboard for Blocked URL Access**
   - Develop a Splunk dashboard to showcase relevant details when users attempt to access blocked URLs. Include information such as timestamp, IP address, and the website being accessed.

![23 dns dashboard](https://github.com/andreiii14/Splunk-SIEM-Project/assets/128039153/e204ff2b-2998-4409-b3f6-0d6cb8addfb0)


## Prevention Measures for Enhanced Security <a name="prevention-measures-for-enhanced-security"></a>

As a SIEM solution primarily focuses on monitoring and alerting, the following preventive measures complement the monitoring capabilities to strengthen the overall security posture of your virtualized environment:

1. **Strong Access Controls:**
   - Limit user privileges and access rights.

2. **Regular System Updates:**
   - Keep software and systems current.

3. **Endpoint Protection:**
   - Utilize advanced security on endpoints.

4. **User Education:**
   - Train users for security awareness.

5. **Network Segmentation:**
   - Isolate critical systems.

6. **Data Backup Strategy:**
   - Implement robust data backup.

7. **Multi-Factor Authentication (MFA):**
   - Enforce additional authentication layers.

## Conclusion <a name="conclusion"></a>

By implementing Splunk as a SIEM solution, this project has significantly enhanced the security of the virtualized environment. Through proactive monitoring, rapid response strategies, and preventive measures, the infrastructure is now fortified against potential threats. Emphasizing anomaly detection and troubleshooting, this SIEM deployment ensures a resilient and secure computing environment, safeguarding critical data integrity and confidentiality.
