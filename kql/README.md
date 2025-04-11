

Let’s level this up 🔥 — here’s a Top 5 KQL Use Cases list used by real businesses in Microsoft Sentinel including both Azure cloud services and virtual machines (Windows & Linux). These are battle-tested queries for threat hunting, behavior analytics, brute-force detection, and cloud abuse detection.


✅ Real-World KQL Queries for Microsoft Sentinel (Across Azure Cloud & Virtual Machines)


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

-- How to simulate this case? Using VPN switching difference locaiton and login with the same id in azure portal

SigninLogs

| summarize Countries = makeset(Location) by UserPrincipalName

| join kind=inner (

SigninLogs    

| summarize by UserPrincipalName, Location, TimeGenerated

 ) on UserPrincipalName


![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/kql/images/KQL05.jpg?raw=true)



🔍 Detects travel-based or impossible logins (e.g. “impossible travel” from two distant locations).




3. 🔐 Elevation of Privileges in Azure AD
 
Detects when a user is added to a privileged group (e.g., Global Admins).

-- How to simulate this case? Create new user id and add the global admiistrator

AuditLogs

| where OperationName == "Add member to role"

| where TargetResources has "Administrator"

| project TimeGenerated, InitiatedBy, TargetResources


![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/kql/images/KQL09.jpg?raw=true)

🔍 Tracks critical changes to Azure AD privileges.


4. 🕵️‍♂️ Linux SSH Brute Force (VM)
   
Same as before — brute force detection for Linux via SSH.


Syslog

| where ProcessName == "sshd" and SyslogMessage has "Failed password"

| parse SyslogMessage with * "from " src_ip " port" *

| summarize FailedAttempts = count() by src_ip, bin(TimeGenerated, 1h)

| where FailedAttempts > 10

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/kql/images/KQL08.jpg?raw=true)



5. 🪟  Brute Force (Windows VM)
   
Same as before — Windows brute force detection .


SecurityEvent

| where EventID == 4625

| summarize FailedAttempts = count() by IpAddress, Account, bin(TimeGenerated, 1h)

| where FailedAttempts > 5

![Alt image](https://github.com/inspiretravel/azure-cloud-soc-homelab/blob/main/kql/images/KQL07.jpg?raw=true)


