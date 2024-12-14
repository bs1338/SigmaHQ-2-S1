# proc_creation_win_susp_script_exec_from_temp

## Title
Suspicious Script Execution From Temp Folder

## ID
a6a39bdb-935c-4f0a-ab77-35f4bbf44d33

## Author
Florian Roth (Nextron Systems), Max Altgelt (Nextron Systems), Tim Shelton

## Date
2021-07-14

## Tags
attack.execution, attack.t1059

## Description
Detects a suspicious script executions from temporary folder

## References
https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/

## False Positives
Administrative scripts

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "\Windows\Temp" OR TgtProcCmdLine containsCIS "\Temporary Internet" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp" OR TgtProcCmdLine containsCIS "\AppData\Roaming\Temp" OR TgtProcCmdLine containsCIS "%TEMP%" OR TgtProcCmdLine containsCIS "%TMP%" OR TgtProcCmdLine containsCIS "%LocalAppData%\Temp") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\cscript.exe")) AND (NOT (TgtProcCmdLine containsCIS " >" OR TgtProcCmdLine containsCIS "Out-File" OR TgtProcCmdLine containsCIS "ConvertTo-Json" OR TgtProcCmdLine containsCIS "-WindowStyle hidden -Verb runAs" OR TgtProcCmdLine containsCIS "\Windows\system32\config\systemprofile\AppData\Local\Temp\Amazon\EC2-Windows\"))))

```