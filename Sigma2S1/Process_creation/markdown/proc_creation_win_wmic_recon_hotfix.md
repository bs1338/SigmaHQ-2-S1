# proc_creation_win_wmic_recon_hotfix

## Title
Windows Hotfix Updates Reconnaissance Via Wmic.EXE

## ID
dfd2fcb7-8bd5-4daa-b132-5adb61d6ad45

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-20

## Tags
attack.execution, attack.t1047

## Description
Detects the execution of wmic with the "qfe" flag in order to obtain information about installed hotfix updates on the system. This is often used by pentester and attacker enumeration scripts

## References
https://github.com/carlospolop/PEASS-ng/blob/fa0f2e17fbc1d86f1fd66338a40e665e7182501d/winPEAS/winPEASbat/winPEAS.bat
https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " qfe" AND TgtProcImagePath endswithCIS "\WMIC.exe"))

```