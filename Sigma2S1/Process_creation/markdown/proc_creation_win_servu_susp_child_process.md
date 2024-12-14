# proc_creation_win_servu_susp_child_process

## Title
Suspicious Serv-U Process Pattern

## ID
58f4ea09-0fc2-4520-ba18-b85c540b0eaf

## Author
Florian Roth (Nextron Systems)

## Date
2021-07-14

## Tags
attack.credential-access, attack.t1555, cve.2021-35211

## Description
Detects a suspicious process pattern which could be a sign of an exploited Serv-U service

## References
https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/

## False Positives
Legitimate uses in which users or programs use the SSH service of Serv-U for remote command execution

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\forfiles.exe" OR TgtProcImagePath endswithCIS "\scriptrunner.exe") AND SrcProcImagePath endswithCIS "\Serv-U.exe"))

```