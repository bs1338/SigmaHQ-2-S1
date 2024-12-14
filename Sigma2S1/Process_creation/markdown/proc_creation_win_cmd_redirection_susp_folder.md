# proc_creation_win_cmd_redirection_susp_folder

## Title
Potentially Suspicious CMD Shell Output Redirect

## ID
8e0bb260-d4b2-4fff-bb8d-3f82118e6892

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-12

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects inline Windows shell commands redirecting output via the ">" symbol to a suspicious location.
This technique is sometimes used by malicious actors in order to redirect the output of reconnaissance commands such as "hostname" and "dir" to files for future exfiltration.


## References
https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/

## False Positives
Legitimate admin or third party scripts used for diagnostic collection might generate some false positives

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\cmd.exe" AND ((TgtProcCmdLine = "*>*%APPDATA%\*" OR TgtProcCmdLine = "*>*%TEMP%\*" OR TgtProcCmdLine = "*>*%TMP%\*" OR TgtProcCmdLine = "*>*%USERPROFILE%\*" OR TgtProcCmdLine = "*>*C:\ProgramData\*" OR TgtProcCmdLine = "*>*C:\Temp\*" OR TgtProcCmdLine = "*>*C:\Users\Public\*" OR TgtProcCmdLine = "*>*C:\Windows\Temp\*") OR ((TgtProcCmdLine containsCIS " >" OR TgtProcCmdLine containsCIS "\">" OR TgtProcCmdLine containsCIS "'>") AND (TgtProcCmdLine containsCIS "C:\Users\" AND TgtProcCmdLine containsCIS "\AppData\Local\")))))

```