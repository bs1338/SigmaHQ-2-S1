# proc_creation_win_schtasks_system

## Title
Schtasks Creation Or Modification With SYSTEM Privileges

## ID
89ca78fd-b37c-4310-b3d3-81a023f83936

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-28

## Tags
attack.execution, attack.persistence, attack.t1053.005

## Description
Detects the creation or update of a scheduled task to run with "NT AUTHORITY\SYSTEM" privileges

## References
https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcCmdLine containsCIS " /change " OR TgtProcCmdLine containsCIS " /create ") AND TgtProcImagePath endswithCIS "\schtasks.exe") AND TgtProcCmdLine containsCIS "/ru " AND (TgtProcCmdLine containsCIS "NT AUT" OR TgtProcCmdLine containsCIS " SYSTEM ")) AND (NOT ((TgtProcCmdLine containsCIS "/Create /F /RU System /SC WEEKLY /TN AviraSystemSpeedupVerify /TR " OR TgtProcCmdLine containsCIS ":\Program Files (x86)\Avira\System Speedup\setup\avira_speedup_setup.exe" OR TgtProcCmdLine containsCIS "/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART\" /RL HIGHEST") OR ((TgtProcCmdLine containsCIS "/TN TVInstallRestore" AND TgtProcCmdLine containsCIS "\TeamViewer_.exe") AND TgtProcImagePath endswithCIS "\schtasks.exe")))))

```