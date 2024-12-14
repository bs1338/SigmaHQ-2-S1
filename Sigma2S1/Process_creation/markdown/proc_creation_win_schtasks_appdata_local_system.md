# proc_creation_win_schtasks_appdata_local_system

## Title
Suspicious Schtasks Execution AppData Folder

## ID
c5c00f49-b3f9-45a6-997e-cfdecc6e1967

## Author
pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-03-15

## Tags
attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001

## Description
Detects the creation of a schtask that executes a file from C:\Users\<USER>\AppData\Local

## References
https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "NT AUT" OR TgtProcCmdLine containsCIS " SYSTEM ") AND (TgtProcCmdLine containsCIS "/Create" AND TgtProcCmdLine containsCIS "/RU" AND TgtProcCmdLine containsCIS "/TR" AND TgtProcCmdLine containsCIS "C:\Users\" AND TgtProcCmdLine containsCIS "\AppData\Local\") AND TgtProcImagePath endswithCIS "\schtasks.exe") AND (NOT (TgtProcCmdLine containsCIS "/TN TVInstallRestore" AND TgtProcImagePath endswithCIS "\schtasks.exe" AND (SrcProcImagePath containsCIS "\AppData\Local\Temp\" AND SrcProcImagePath containsCIS "TeamViewer_.exe")))))

```