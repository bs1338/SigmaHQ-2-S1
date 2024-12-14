# proc_creation_win_winrm_susp_child_process

## Title
Suspicious Processes Spawned by WinRM

## ID
5cc2cda8-f261-4d88-a2de-e9e193c86716

## Author
Andreas Hunkeler (@Karneades), Markus Neis

## Date
2021-05-20

## Tags
attack.t1190, attack.initial-access, attack.persistence, attack.privilege-escalation

## Description
Detects suspicious processes including shells spawnd from WinRM host process

## References
Internal Research

## False Positives
Legitimate WinRM usage

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wsl.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\whoami.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe") AND SrcProcImagePath endswithCIS "\wsmprovhost.exe"))

```