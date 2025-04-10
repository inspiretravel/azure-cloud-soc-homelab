# azure-cloud-soc-homelab
🚀 Azure Cloud Security Operations Lab
Detection, Monitoring, and Response with Microsoft Sentinel

________________________________________
🔍 Project Overview:

This home lab builds a simulated, enterprise-grade Security Operations Center (SOC) using Microsoft Azure. It integrates Microsoft Sentinel (SIEM), Log Analytics, and Microsoft Defender for Cloud to detect, investigate, and respond to real-world threats. The lab aligns with ISO 27001 and Australia’s Essential Eight, providing compliance-driven security operations experience.

________________________________________
🎯 Objectives:

•	Deploy and configure Microsoft Sentinel as a cloud-native SIEM.

•	Ingest logs from multiple sources (Windows/Linux VMs, firewall, Defender).

•	Write and execute custom KQL threat detection rules.

•	Respond to incidents using automated playbooks and NSG rules.

•	Build threat dashboards with geolocation and visual analytics.

•	Align with compliance standards and cybersecurity frameworks.

________________________________________
🧩 Core Components:

•Sentinel & Log Analytics Central log collection and analysis from virtual assets and security tools.

•Threat Detection KQL-based detection rules for brute-force, access attempts, and anomalies.

•Incident Response	Manual and automated workflows to mitigate threats.

•Visualization	Dashboards with maps, charts, and timelines for visibility.

________________________________________
🔧 Prerequisites

•	Azure subscription (free or pay-as-you-go)

•	Familiarity with VMs, Azure Portal, and basic security concepts

________________________________________

🛠️ Step 1: Build the Environment

[🔹 Create Resource Group]

-- Search or click resource groups >  create > 
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/01%20Create%20RG1.jpg?raw=true) 
-- Input resource group name DL-RG1 and region (Asia Pacific)australia east

-- Click next or Review+create
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/02%20Create%20RG2.jpg?raw=true)

-- Go back to resource group page
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/03%20Create%20RG3.jpg?raw=true)


[🔹 Deploy Virtual Machines]

Create window machine and Linux machine for sending the log to Sentinel

•	Windows 10 Pro: Enable RDP, configure account info, network interface.

-- Search or click virtual machine >  create >

•	Windows 10 Pro, assign the same region as resource groups

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/04%20Create%20VM%20win01.jpg?raw=true)


•	Ubuntu 20.04: Enable SSH, configure ufw, assign public IP.


________________________________________

📊 Step 2: Configure Log Analytics

[🔹 Create Log Analytics Workspace]

-- Search or click Log Analytics  >  create > 

-- Input same region and same resource group and input the log analytics name as DLGR1-LA

  ![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/08%20Create%20LogAnalytics%20workspace01.jpg?raw=true)
  ![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/09%20Create%20LogAnalytics%20workspace02.jpg?raw=true)

  

[🔹 Enable Defender for Cloud]

•	Onboard Windows VM via Azure Security Center > Microsoft Defender portal.

-- Make sure go to subscription > environment setting > turn on the necessary plan (e.g. defender CPSM, servers etc)
 
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/10%20MS%20for%20cloud%2001.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/11%20MS%20for%20cloud%2002.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/12%20MS%20for%20cloud%2003.jpg?raw=true)


________________________________________

🧠 Step 3: Activate Microsoft Sentinel

[🔹 Enable Sentinel]

•	Azure Portal > Microsoft Sentinel > + Add > Select DLGR1-LA

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/23%20link%20with%20Sentinel01.jpg?raw=true)

[🔹 Add Data Connectors]

•	Enable for Windows Security Events, Syslog, Defender for cloud etc

-- Click data connectors

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/25%20link%20with%20Sentinel02.jpg?raw=true)

-- Click Content hub > tick necessary item > Install

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/26%20link%20with%20Sentinel03.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/27%20link%20with%20Sentinel04.jpg?raw=true)

[🔹 Create Data Collection Rule]

-- Once installation is done > go to the desired content title > manage

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/29%20Create%20Data%20connector01.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/30%20Create%20Data%20connector02.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/32%20Create%20Data%20connector03.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/33%20Create%20Data%20connector04.jpg?raw=true)

-- Check the status of data connectors

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/35%20Create%20Data%20connector05.jpg?raw=true)



[🔹 Verify Log Ingestion]

SecurityEvent 

| take 10

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/81%20Sentinel%20logs%20checking.jpg?raw=true)



[🔗 Compliance] 

Applied in step 1 to 3

| ISO 27001                                      | Essential Eight        |
|-----------------------------------------------|----------------------------|
| Event logging enabled      |Application Control supported by log visibility |
| Integrity of logs via centralized collection| |
| Admin/operator activity tracking |Admin privilege monitoring|


________________________________________

🔎 Step 4: Threat Detection with KQL

[🔹 Brute-Force Detection (Windows)]

SecurityEvent

| where EventID == 4625

| summarize Attempts = count() by IpAddress, Computer

| where Attempts > 10

| order by Attempts desc

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/82%20KQL%20Brute%20Force.jpg?raw=true)

Finding: Within 24 hours, the most bruce force attack came from Netherlands

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/83%20KQL%20Brute%20Force%20IP.jpg?raw=true)


[🔹 SSH Failures (Linux)]

Syslog
| where Facility == "auth" and Message contains "Failed password"
| summarize Count = count() by HostIP
| where Count > 5

[🔹 Create Alert Rules]

•	Sentinel > Analytics > + Create > Paste KQL > Set frequency & threshold

-- Create Analytics rule for Brute force Window case
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/84%20Analytics%20rule%20Brute%20Force.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/85%20Analytics%20rule%20Brute%20Force%2001.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/86%20Analytics%20rule%20Brute%20Force%2002.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/87%20Analytics%20rule%20Brute%20Force%2003.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/88%20Analytics%20rule%20Brute%20Force%2004.jpg?raw=true)



[🔗 Compliance]

| ISO 27001                                      | Essential Eight        |
|-----------------------------------------------|----------------------------|
| Enhanced log-based detections     |Detection supports patching processes |


________________________________________

⚠️ Step 5: Incident Response

🔹 Threat Hunting

•	Sentinel > Hunting > Run saved/custom queries

🔹 Block Malicious IPs

az network nsg rule create \
  --resource-group CyberSecLab \
  --nsg-name NSG1 \
  --name BlockMaliciousIP \
  --priority 100 \
  --source-address-prefixes 1.2.3.4 \
  --destination-port-ranges 3389 \
  --access Deny \
  --protocol Tcp \
  --direction Inbound
  
🔹 Automate Response

•	Sentinel > Automation > + Playbook (Logic App for Slack/email alerts)

🔗 Compliance

•	ISO 27001 A.16.1.5: Structured response workflow
•	Essential Eight: Enhances access control alongside MFA
________________________________________

🌍 Step 6: Visualize Threats

🔹 Build Dashboards

SecurityEvent
| summarize Count = count() by SourceIP
| extend Geo = geo_info_from_ip(SourceIP)
•	Create workbook > Add map, bar chart, and table visuals
•	Save as GeoThreats and pin to Azure dashboard

🔗 Compliance

•	ISO 27001 A.12.4.1: Log visualization enhances event review

•	Essential Eight: Improves threat visibility and response time

________________________________________

📚 Compliance Summary:

| ISO 27001|       
|-----------------------------------------------|
| Control Implementation: Log monitoring and analysis, Threat response workflow| 


| Essential Eight                            |     |
|-----------------------------------------------|----------------------------|
| Strategy   |Implementation |
|Patch Applications| Detection of unpatched system activity|
|Restrict Administrative Privileges| Monitoring elevated access and usage|

________________________________________

📌 Resources:

•	GitHub: Azure Sentinel Samples

•	YouTube: Microsoft Mechanics – Sentinel Setup, John Savill – Azure Lab Guide

________________________________________

📦 Deliverables:

•	Fully configured Azure SOC lab (Sentinel + VMs + Defender)

•	KQL rules and alerting workflows

•	Geolocation dashboard



