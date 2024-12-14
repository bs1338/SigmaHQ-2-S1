# proc_creation_win_registry_logon_script

## Title
Potential Persistence Via Logon Scripts - CommandLine

## ID
21d856f9-9281-4ded-9377-51a1a6e2a432

## Author
Tom Ueltschi (@c_APT_ure)

## Date
2019-01-12

## Tags
attack.persistence, attack.t1037.001

## Description
Detects the addition of a new LogonScript to the registry value "UserInitMprLogonScript" for potential persistence

## References
https://cocomelonc.github.io/persistence/2022/12/09/malware-pers-20.html

## False Positives
Legitimate addition of Logon Scripts via the command line by administrators or third party tools

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "UserInitMprLogonScript")

```