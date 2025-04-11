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

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/93%20create%20linux%20VM.jpg?raw=true)

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

-- Select select data source and destination

Windows example
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/29%20Create%20Data%20connector01.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/30%20Create%20Data%20connector02.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/32%20Create%20Data%20connector03.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/33%20Create%20Data%20connector04.jpg?raw=true)

Linux Example
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/93%20linux%20VM%20collection%20log.jpg?raw=true)

-- Check the status of data connectors

Under Data connectors page
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/35%20Create%20Data%20connector05.jpg?raw=true)

Under Log Analytics workspace > Agent
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/94%20LAW%20linux%20connect%20status.jpg?raw=true)


[🔹 Verify Log Ingestion]

'''kql
SecurityEvent 

| take 10

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/81%20Sentinel%20logs%20checking.jpg?raw=true)



[🔗 Compliance] 

Applied in step 1 to 3

|ISO 27001| Essential Eight|
|-----------------------------------------------|----------------------------|
|Event logging enabled|Application Control supported by log visibility|
|Integrity of logs via centralized collection||
|Admin/operator activity tracking|Admin privilege monitoring|


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
| where Facility == "auth" and SyslogMessage contains "invalid user"
| summarize Count = count() by HostIP
| where Count > 5

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/95%20brute%20force%20linux.jpg?raw=true)

[🔹 Create Alert Rules]

•	Sentinel > Analytics > + Create > Paste KQL > Set frequency & threshold

-- Create Analytics rule for Brute force Window case
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/84%20Analytics%20rule%20Brute%20Force.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/85%20Analytics%20rule%20Brute%20Force%2001.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/86%20Analytics%20rule%20Brute%20Force%2002.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/87%20Analytics%20rule%20Brute%20Force%2003.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/88%20Analytics%20rule%20Brute%20Force%2004.jpg?raw=true)



[🔗 Compliance]

|ISO 27001|Essential Eight|
|-----------------------------------------------|----------------------------|
|Enhanced log-based detections|Detection supports patching processes|

________________________________________

⚠️ Step 5: Incident Response

[🔹Incident Handling]

Sentinel > Incidents> View full detail
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/89%20Incident%20dashboard.jpg?raw=true)

-- Assign the incident to SOC team member

-- Change the incident status, put the incident comment 

-- Click Investigate > understand the incident workflow

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/89%20Incident%20dashboard01.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/89%20Incident%20dashboard02.jpg?raw=true)

[🔹 Threat Hunting]

--	Sentinel > Hunting > Run saved/custom queries

-- Used the existing template to create one hunting query 
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/90%20Hunting%2001.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/90%20Hunting%2002.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/90%20Hunting%2003.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/90%20Hunting%2004.jpg?raw=true)


[🔹 Block Malicious IPs]

-- network nsg rule > create 

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/91%20win%20network%20security%20group.jpg?raw=true)


[🔗 Compliance]

|ISO 27001|Essential Eight|
|-----------------------------------------------|----------------------------|
|Structured response workflow|Enhances access control alongside MFA|

________________________________________

🌍 Step 6: Visualize Threats

[🔹 Build Dashboards]

-- Create watchlist and upload csv file including ip address source by country

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/55%20create%20workbook01.JPG?raw=true)

-- Named the watchlist as geoip, alias as geoip, searchkey as network
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/57%20Create%20workbook02.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/58%20Create%20workbook03.jpg?raw=true)

-- Wait around 5 mins and check the watchlist items
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/59%20Create%20workbook04.jpg?raw=true)

[🔹 Verify Log Ingestion and create attackmap]

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/60%20Create%20workbook01.jpg?raw=true)

-- Create workbook > Add map, bar chart, and table visuals

-- Save as Attack Map and can pin to Azure dashboard

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/61%20Create%20Workbook02.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/images/62%20Create%20workbook03.jpg?raw=true)


[🔗 Compliance]

|ISO 27001|Essential Eight|
|-----------------------------------------------|----------------------------|
|Log visualization enhances event review|Improves threat visibility and response time|

________________________________________

📚 Compliance Summary:

|ISO 27001|       
|-----------------------------------------------|
|Control Implementation: Log monitoring and analysis, Threat response workflow| 


| Essential Eight||
|-----------------------------------------------|----------------------------|
|Strategy|Implementation|
|Patch Applications|Detection of unpatched system activity|
|Restrict Administrative Privileges|Monitoring elevated access and usage|

________________________________________

📌 Resources:

•	GitHub: Azure Sentinel Samples

•	YouTube: Microsoft Mechanics – Sentinel Setup, John Savill – Azure Lab Guide, Josh Madakor 

________________________________________

📦 Deliverables:

•	Fully configured Azure SOC lab (Sentinel + VMs + Defender)

•	KQL rules and alerting workflows

•	Geolocation dashboard



