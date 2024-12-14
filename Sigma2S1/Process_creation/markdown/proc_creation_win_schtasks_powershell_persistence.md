# proc_creation_win_schtasks_powershell_persistence

## Title
Potential Persistence Via Powershell Search Order Hijacking - Task

## ID
b66474aa-bd92-4333-a16c-298155b120df

## Author
pH-T (Nextron Systems), Florian Roth (Nextron Systems)

## Date
2022-04-08

## Tags
attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001

## Description
Detects suspicious powershell execution via a schedule task where the command ends with an suspicious flags to hide the powershell instance instead of executeing scripts or commands. This could be a sign of persistence via PowerShell "Get-Variable" technique as seen being used in Colibri Loader

## References
https://blog.malwarebytes.com/threat-intelligence/2022/04/colibri-loader-combines-task-scheduler-and-powershell-in-clever-persistence-technique/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS " -windowstyle hidden" OR TgtProcCmdLine endswithCIS " -w hidden" OR TgtProcCmdLine endswithCIS " -ep bypass" OR TgtProcCmdLine endswithCIS " -noni") AND (SrcProcCmdLine containsCIS "-k netsvcs" AND SrcProcCmdLine containsCIS "-s Schedule") AND SrcProcImagePath = "C:\WINDOWS\System32\svchost.exe"))

```