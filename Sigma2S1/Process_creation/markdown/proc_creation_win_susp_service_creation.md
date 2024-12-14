# proc_creation_win_susp_service_creation

## Title
Suspicious New Service Creation

## ID
17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-14

## Tags
attack.persistence, attack.privilege-escalation, attack.t1543.003

## Description
Detects creation of a new service via "sc" command or the powershell "new-service" cmdlet with suspicious binary paths

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md
https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "New-Service" AND TgtProcCmdLine containsCIS "-BinaryPathName") OR ((TgtProcCmdLine containsCIS "create" AND TgtProcCmdLine containsCIS "binPath=") AND TgtProcImagePath endswithCIS "\sc.exe")) AND (TgtProcCmdLine containsCIS "powershell" OR TgtProcCmdLine containsCIS "mshta" OR TgtProcCmdLine containsCIS "wscript" OR TgtProcCmdLine containsCIS "cscript" OR TgtProcCmdLine containsCIS "svchost" OR TgtProcCmdLine containsCIS "dllhost" OR TgtProcCmdLine containsCIS "cmd " OR TgtProcCmdLine containsCIS "cmd.exe /c" OR TgtProcCmdLine containsCIS "cmd.exe /k" OR TgtProcCmdLine containsCIS "cmd.exe /r" OR TgtProcCmdLine containsCIS "rundll32" OR TgtProcCmdLine containsCIS "C:\Users\Public" OR TgtProcCmdLine containsCIS "\Downloads\" OR TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "\Microsoft\Windows\Start Menu\Programs\Startup\" OR TgtProcCmdLine containsCIS "C:\Windows\TEMP\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp")))

```