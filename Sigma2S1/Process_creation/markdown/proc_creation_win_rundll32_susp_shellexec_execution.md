# proc_creation_win_rundll32_susp_shellexec_execution

## Title
Suspicious Usage Of ShellExec_RunDLL

## ID
d87bd452-6da1-456e-8155-7dc988157b7d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-01

## Tags
attack.defense-evasion

## Description
Detects suspicious usage of the ShellExec_RunDLL function to launch other commands as seen in the the raspberry-robin attack

## References
https://redcanary.com/blog/raspberry-robin/
https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/
https://github.com/SigmaHQ/sigma/issues/1009

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "ShellExec_RunDLL" AND (TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "\Temp\" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "comspec" OR TgtProcCmdLine containsCIS "iex" OR TgtProcCmdLine containsCIS "Invoke-" OR TgtProcCmdLine containsCIS "msiexec" OR TgtProcCmdLine containsCIS "odbcconf" OR TgtProcCmdLine containsCIS "regsvr32")))

```