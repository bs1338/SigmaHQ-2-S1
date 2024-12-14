# proc_creation_win_mssql_veaam_susp_child_processes

## Title
Suspicious Child Process Of Veeam Dabatase

## ID
d55b793d-f847-4eea-b59a-5ab09908ac90

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-04

## Tags
attack.initial-access, attack.persistence, attack.privilege-escalation

## Description
Detects suspicious child processes of the Veeam service process. This could indicate potential RCE or SQL Injection.

## References
https://labs.withsecure.com/publications/fin7-target-veeam-servers

## False Positives


## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcCmdLine containsCIS "VEEAMSQL" AND SrcProcImagePath endswithCIS "\sqlservr.exe") AND (((TgtProcCmdLine containsCIS "-ex " OR TgtProcCmdLine containsCIS "bypass" OR TgtProcCmdLine containsCIS "cscript" OR TgtProcCmdLine containsCIS "DownloadString" OR TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://" OR TgtProcCmdLine containsCIS "mshta" OR TgtProcCmdLine containsCIS "regsvr32" OR TgtProcCmdLine containsCIS "rundll32" OR TgtProcCmdLine containsCIS "wscript" OR TgtProcCmdLine containsCIS "copy ") AND (TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wsl.exe" OR TgtProcImagePath endswithCIS "\wt.exe")) OR (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe" OR TgtProcImagePath endswithCIS "\netstat.exe" OR TgtProcImagePath endswithCIS "\nltest.exe" OR TgtProcImagePath endswithCIS "\ping.exe" OR TgtProcImagePath endswithCIS "\tasklist.exe" OR TgtProcImagePath endswithCIS "\whoami.exe"))))

```