# proc_creation_win_powershell_import_cert_susp_locations

## Title
Root Certificate Installed From Susp Locations

## ID
5f6a601c-2ecb-498b-9c33-660362323afa

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-09

## Tags
attack.defense-evasion, attack.t1553.004

## Description
Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.

## References
https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate?view=windowsserver2022-ps

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS ":\Windows\TEMP\" OR TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "\Downloads\" OR TgtProcCmdLine containsCIS "\Perflogs\" OR TgtProcCmdLine containsCIS ":\Users\Public\") AND (TgtProcCmdLine containsCIS "Import-Certificate" AND TgtProcCmdLine containsCIS " -FilePath " AND TgtProcCmdLine containsCIS "Cert:\LocalMachine\Root")))

```