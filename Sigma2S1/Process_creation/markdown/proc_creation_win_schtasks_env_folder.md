# proc_creation_win_schtasks_env_folder

## Title
Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE

## ID
81325ce1-be01-4250-944f-b4789644556f

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-21

## Tags
attack.execution, attack.t1053.005

## Description
Detects Schtask creations that point to a suspicious folder or an environment variable often used by malware

## References
https://www.welivesecurity.com/2022/01/18/donot-go-do-not-respawn/
https://www.joesandbox.com/analysis/514608/0/html#324415FF7D8324231381BAD48A052F85DF04
https://blog.talosintelligence.com/gophish-powerrat-dcrat/

## False Positives
Benign scheduled tasks creations or executions that happen often during software installations
Software that uses the AppData folder and scheduled tasks to update the software in the AppData folders

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcCmdLine containsCIS ":\Perflogs" OR TgtProcCmdLine containsCIS ":\Users\All Users\" OR TgtProcCmdLine containsCIS ":\Users\Default\" OR TgtProcCmdLine containsCIS ":\Users\Public" OR TgtProcCmdLine containsCIS ":\Windows\Temp" OR TgtProcCmdLine containsCIS "\AppData\Local\" OR TgtProcCmdLine containsCIS "\AppData\Roaming\" OR TgtProcCmdLine containsCIS "%AppData%" OR TgtProcCmdLine containsCIS "%Public%") AND (TgtProcCmdLine containsCIS " /create " AND TgtProcImagePath endswithCIS "\schtasks.exe")) OR (SrcProcCmdLine endswithCIS "\svchost.exe -k netsvcs -p -s Schedule" AND (TgtProcCmdLine containsCIS ":\Perflogs" OR TgtProcCmdLine containsCIS ":\Windows\Temp" OR TgtProcCmdLine containsCIS "\Users\Public" OR TgtProcCmdLine containsCIS "%Public%"))) AND (NOT ((TgtProcCmdLine containsCIS "/Create /Xml \"C:\Users\" AND TgtProcCmdLine containsCIS "\AppData\Local\Temp\.CR." AND TgtProcCmdLine containsCIS "Avira_Security_Installation.xml") OR ((TgtProcCmdLine containsCIS ".tmp\UpdateFallbackTask.xml" OR TgtProcCmdLine containsCIS ".tmp\WatchdogServiceControlManagerTimeout.xml" OR TgtProcCmdLine containsCIS ".tmp\SystrayAutostart.xml" OR TgtProcCmdLine containsCIS ".tmp\MaintenanceTask.xml") AND (TgtProcCmdLine containsCIS "/Create /F /TN" AND TgtProcCmdLine containsCIS "/Xml " AND TgtProcCmdLine containsCIS "\AppData\Local\Temp\is-" AND TgtProcCmdLine containsCIS "Avira_")) OR (TgtProcCmdLine containsCIS "\AppData\Local\Temp\" AND TgtProcCmdLine containsCIS "/Create /TN \"klcp_update\" /XML " AND TgtProcCmdLine containsCIS "\klcp_update_task.xml") OR (SrcProcCmdLine containsCIS "unattended.ini" OR TgtProcCmdLine containsCIS "update_task.xml") OR TgtProcCmdLine containsCIS "/Create /TN TVInstallRestore /TR"))))

```