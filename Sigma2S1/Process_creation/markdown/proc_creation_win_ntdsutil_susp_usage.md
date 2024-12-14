# proc_creation_win_ntdsutil_susp_usage

## Title
Suspicious Usage Of Active Directory Diagnostic Tool (ntdsutil.exe)

## ID
a58353df-af43-4753-bad0-cd83ef35eef5

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-14

## Tags
attack.credential-access, attack.t1003.003

## Description
Detects execution of ntdsutil.exe to perform different actions such as restoring snapshots...etc.

## References
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731620(v=ws.11)
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/espionage-asia-governments

## False Positives
Legitimate usage to restore snapshots
Legitimate admin activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "snapshot" AND TgtProcCmdLine containsCIS "mount ") OR (TgtProcCmdLine containsCIS "ac" AND TgtProcCmdLine containsCIS " i" AND TgtProcCmdLine containsCIS " ntds")) AND TgtProcImagePath endswithCIS "\ntdsutil.exe"))

```