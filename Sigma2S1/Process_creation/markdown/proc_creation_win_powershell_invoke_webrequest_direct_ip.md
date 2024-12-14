# proc_creation_win_powershell_invoke_webrequest_direct_ip

## Title
Suspicious Invoke-WebRequest Execution With DirectIP

## ID
1edff897-9146-48d2-9066-52e8d8f80a2f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-21

## Tags
attack.command-and-control, attack.t1105

## Description
Detects calls to PowerShell with Invoke-WebRequest cmdlet using direct IP access

## References
https://www.huntress.com/blog/critical-vulnerabilities-in-papercut-print-management-software

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "curl " OR TgtProcCmdLine containsCIS "Invoke-WebRequest" OR TgtProcCmdLine containsCIS "iwr " OR TgtProcCmdLine containsCIS "wget ") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (TgtProcCmdLine containsCIS "://1" OR TgtProcCmdLine containsCIS "://2" OR TgtProcCmdLine containsCIS "://3" OR TgtProcCmdLine containsCIS "://4" OR TgtProcCmdLine containsCIS "://5" OR TgtProcCmdLine containsCIS "://6" OR TgtProcCmdLine containsCIS "://7" OR TgtProcCmdLine containsCIS "://8" OR TgtProcCmdLine containsCIS "://9")))

```