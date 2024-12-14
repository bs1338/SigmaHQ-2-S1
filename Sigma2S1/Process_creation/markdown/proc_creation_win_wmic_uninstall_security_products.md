# proc_creation_win_wmic_uninstall_security_products

## Title
Potential Tampering With Security Products Via WMIC

## ID
847d5ff3-8a31-4737-a970-aeae8fe21765

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2021-01-30

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects uninstallation or termination of security products using the WMIC utility

## References
https://twitter.com/cglyer/status/1355171195654709249
https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
https://www.mandiant.com/resources/unc2165-shifts-to-evade-sanctions
https://research.nccgroup.com/2022/08/19/back-in-black-unlocking-a-lockbit-3-0-ransomware-attack/
https://www.trendmicro.com/en_us/research/23/a/vice-society-ransomware-group-targets-manufacturing-companies.html

## False Positives
Legitimate administration

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "wmic" AND TgtProcCmdLine containsCIS "product where " AND TgtProcCmdLine containsCIS "call" AND TgtProcCmdLine containsCIS "uninstall" AND TgtProcCmdLine containsCIS "/nointeractive") OR ((TgtProcCmdLine containsCIS "call delete" OR TgtProcCmdLine containsCIS "call terminate") AND (TgtProcCmdLine containsCIS "wmic" AND TgtProcCmdLine containsCIS "caption like ")) OR (TgtProcCmdLine containsCIS "process " AND TgtProcCmdLine containsCIS "where " AND TgtProcCmdLine containsCIS "delete")) AND (TgtProcCmdLine containsCIS "%carbon%" OR TgtProcCmdLine containsCIS "%cylance%" OR TgtProcCmdLine containsCIS "%endpoint%" OR TgtProcCmdLine containsCIS "%eset%" OR TgtProcCmdLine containsCIS "%malware%" OR TgtProcCmdLine containsCIS "%Sophos%" OR TgtProcCmdLine containsCIS "%symantec%" OR TgtProcCmdLine containsCIS "Antivirus" OR TgtProcCmdLine containsCIS "AVG " OR TgtProcCmdLine containsCIS "Carbon Black" OR TgtProcCmdLine containsCIS "CarbonBlack" OR TgtProcCmdLine containsCIS "Cb Defense Sensor 64-bit" OR TgtProcCmdLine containsCIS "Crowdstrike Sensor" OR TgtProcCmdLine containsCIS "Cylance " OR TgtProcCmdLine containsCIS "Dell Threat Defense" OR TgtProcCmdLine containsCIS "DLP Endpoint" OR TgtProcCmdLine containsCIS "Endpoint Detection" OR TgtProcCmdLine containsCIS "Endpoint Protection" OR TgtProcCmdLine containsCIS "Endpoint Security" OR TgtProcCmdLine containsCIS "Endpoint Sensor" OR TgtProcCmdLine containsCIS "ESET File Security" OR TgtProcCmdLine containsCIS "LogRhythm System Monitor Service" OR TgtProcCmdLine containsCIS "Malwarebytes" OR TgtProcCmdLine containsCIS "McAfee Agent" OR TgtProcCmdLine containsCIS "Microsoft Security Client" OR TgtProcCmdLine containsCIS "Sophos Anti-Virus" OR TgtProcCmdLine containsCIS "Sophos AutoUpdate" OR TgtProcCmdLine containsCIS "Sophos Credential Store" OR TgtProcCmdLine containsCIS "Sophos Management Console" OR TgtProcCmdLine containsCIS "Sophos Management Database" OR TgtProcCmdLine containsCIS "Sophos Management Server" OR TgtProcCmdLine containsCIS "Sophos Remote Management System" OR TgtProcCmdLine containsCIS "Sophos Update Manager" OR TgtProcCmdLine containsCIS "Threat Protection" OR TgtProcCmdLine containsCIS "VirusScan" OR TgtProcCmdLine containsCIS "Webroot SecureAnywhere" OR TgtProcCmdLine containsCIS "Windows Defender")))

```