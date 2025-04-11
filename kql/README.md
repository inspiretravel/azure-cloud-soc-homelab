

Let’s level this up 🔥 — here’s a Top 10 KQL Use Cases list used by real businesses in Microsoft Sentinel including both Azure cloud services and virtual machines (Windows & Linux). These are battle-tested queries for threat hunting, behavior analytics, brute-force detection, and cloud abuse detection.


✅ Top 10 Real-World KQL Queries for Microsoft Sentinel (Across Azure Cloud & Virtual Machines)


1. 🚨 Azure Sign-In Brute Force Detection

Detects multiple failed sign-ins from the same IP within a short time.

-- How to simulate this case? Create new user id and login multiple time in azure portal.
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/kql/images/KQL02.jpg?raw=true)

-- Vertify the log 
![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/kql/images/KQL01.jpg?raw=true)

-- Sentinel > Log

SigninLogs

| where ResultType != 0 // failed login

| summarize FailedAttempts = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 1h)

| where FailedAttempts > 5

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/kql/images/KQL03.jpg?raw=true)


🔍 Catches brute-force attempts against Azure AD accounts.



2. 🧠 Unusual User Sign-in Locations
   
Identifies sign-ins from geographic locations not seen before for a user.


SigninLogs

| summarize Countries = makeset(Location) by UserPrincipalName

| join kind=inner (

SigninLogs    

| summarize by UserPrincipalName, Location, TimeGenerated

 ) on UserPrincipalName


![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/kql/images/KQL05.jpg?raw=true)



🔍 Detects travel-based or impossible logins (e.g. “impossible travel” from two distant locations).



3. 🛠️ Azure Resource Modification by Non-Admin
   
Alerts when non-admins change sensitive resources like NSGs or Key Vaults.


AzureActivity 

| where OperationNameValue contains "Write"

| where ResourceProviderValue in ("Microsoft.Network/networkSecurityGroups", "Microsoft.KeyVault/vaults")

| where Caller != "admin@yourdomain.com"

| project TimeGenerated, Caller, OperationNameValue, Resource, ResourceGroup


🔍 Flags potential misuse or insider threats.


4. 🔐 Elevation of Privileges in Azure AD
 
Detects when a user is added to a privileged group (e.g., Global Admins).


AuditLogs

| where OperationName == "Add member to role"

| where TargetResources has "Company Administrator"

| project TimeGenerated, InitiatedBy, TargetResources

🔍 Tracks critical changes to Azure AD privileges.


5. 🕵️‍♂️ Linux SSH Brute Force (VM)
   
Same as before — brute force detection for Linux via SSH.


Syslog

| where ProcessName == "sshd" and SyslogMessage has "Failed password"

| parse SyslogMessage with * "from " src_ip " port" *

| summarize FailedAttempts = count() by src_ip, bin(TimeGenerated, 1h)

| where FailedAttempts > 10

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/kql/images/KQL08.jpg?raw=true)



6. 🪟  Brute Force (Windows VM)
   
Same as before — Windows brute force detection .


SecurityEvent

| where EventID == 4625

| summarize FailedAttempts = count() by IpAddress, Account, bin(TimeGenerated, 1h)

| where FailedAttempts > 5

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/kql/images/KQL07.jpg?raw=true)


7. 🌐 Unusual Outbound Network Traffic (Cloud & VMs)
Detects VM or Azure workload traffic to rare or suspicious locations.


AzureNetworkAnalytics_CL

| where Direction_s == "Outbound"

| where RemoteIPCountry !in ("Australia", "United States")

| summarize Connections = count() by RemoteIPCountry, RemoteIP, bin(TimeGenerated, 1h)

| where Connections > 5

🔍 Helps detect beaconing or data exfiltration.


8. 🧬 Rare Process Execution (Windows/Linux)
   
Looks for rarely seen processes across all endpoints.


DeviceProcessEvents

| summarize Count = count() by FileName

| order by Count asc

| take 20


🔍 Detects unknown malware or scripts.

9. 🧭 Impossible Travel Detection

    
Logins from geographically impossible locations based on last login.


let timeFrame = 1d;

SigninLogs

| where TimeGenerated > ago(timeFrame)

| project UserPrincipalName, Location, TimeGenerated, IPAddress

| join kind=inner (

SigninLogs

| where TimeGenerated > ago(timeFrame)

| project UserPrincipalName, Location, TimeGenerated, IPAddress

) on UserPrincipalName

| where abs(datetime_diff("minute", TimeGenerated1, TimeGenerated2)) < 60

| where Location1 != Location2

🔍 Correlates two login events that couldn't happen due to time + location constraints.


10. 🧪 Defender for Endpoint Alert with Process Context
    
Correlates an alert with process execution on a VM.


AlertEvidence

| where EntityType == "Process"

| join kind=inner ( 

DeviceProcessEvents

| project Timestamp, FileName, ProcessCommandLine, DeviceName   

) on $left.DeviceName == $right.DeviceName

| project Timestamp, FileName, ProcessCommandLine

🔍 Links an alert to actual command-line evidence from Defender for Endpoint.



