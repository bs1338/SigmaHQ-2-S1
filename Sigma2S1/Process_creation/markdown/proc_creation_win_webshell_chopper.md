# proc_creation_win_webshell_chopper

## Title
Chopper Webshell Process Pattern

## ID
fa3c117a-bc0d-416e-a31b-0c0e80653efb

## Author
Florian Roth (Nextron Systems), MSTI (query)

## Date
2022-10-01

## Tags
attack.persistence, attack.t1505.003, attack.t1018, attack.t1033, attack.t1087

## Description
Detects patterns found in process executions cause by China Chopper like tiny (ASPX) webshells

## References
https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "&ipconfig&echo" OR TgtProcCmdLine containsCIS "&quser&echo" OR TgtProcCmdLine containsCIS "&whoami&echo" OR TgtProcCmdLine containsCIS "&c:&echo" OR TgtProcCmdLine containsCIS "&cd&echo" OR TgtProcCmdLine containsCIS "&dir&echo" OR TgtProcCmdLine containsCIS "&echo [E]" OR TgtProcCmdLine containsCIS "&echo [S]") AND (TgtProcImagePath endswithCIS "\w3wp.exe" OR SrcProcImagePath endswithCIS "\w3wp.exe")))

```