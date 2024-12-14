# proc_creation_win_powershell_base64_iex

## Title
PowerShell Base64 Encoded IEX Cmdlet

## ID
88f680b8-070e-402c-ae11-d2914f2257f1

## Author
Florian Roth (Nextron Systems)

## Date
2019-08-23

## Tags
attack.execution, attack.t1059.001

## Description
Detects usage of a base64 encoded "IEX" cmdlet in a process command line

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "SUVYIChb" OR TgtProcCmdLine containsCIS "lFWCAoW" OR TgtProcCmdLine containsCIS "JRVggKF" OR TgtProcCmdLine containsCIS "aWV4IChb" OR TgtProcCmdLine containsCIS "lleCAoW" OR TgtProcCmdLine containsCIS "pZXggKF" OR TgtProcCmdLine containsCIS "aWV4IChOZX" OR TgtProcCmdLine containsCIS "lleCAoTmV3" OR TgtProcCmdLine containsCIS "pZXggKE5ld" OR TgtProcCmdLine containsCIS "SUVYIChOZX" OR TgtProcCmdLine containsCIS "lFWCAoTmV3" OR TgtProcCmdLine containsCIS "JRVggKE5ld" OR TgtProcCmdLine containsCIS "SUVYKF" OR TgtProcCmdLine containsCIS "lFWChb" OR TgtProcCmdLine containsCIS "JRVgoW" OR TgtProcCmdLine containsCIS "aWV4KF" OR TgtProcCmdLine containsCIS "lleChb" OR TgtProcCmdLine containsCIS "pZXgoW" OR TgtProcCmdLine containsCIS "aWV4KE5ld" OR TgtProcCmdLine containsCIS "lleChOZX" OR TgtProcCmdLine containsCIS "pZXgoTmV3" OR TgtProcCmdLine containsCIS "SUVYKE5ld" OR TgtProcCmdLine containsCIS "lFWChOZX" OR TgtProcCmdLine containsCIS "JRVgoTmV3" OR TgtProcCmdLine containsCIS "SUVYKCgn" OR TgtProcCmdLine containsCIS "lFWCgoJ" OR TgtProcCmdLine containsCIS "JRVgoKC" OR TgtProcCmdLine containsCIS "aWV4KCgn" OR TgtProcCmdLine containsCIS "lleCgoJ" OR TgtProcCmdLine containsCIS "pZXgoKC") OR (TgtProcCmdLine containsCIS "SQBFAFgAIAAoAFsA" OR TgtProcCmdLine containsCIS "kARQBYACAAKABbA" OR TgtProcCmdLine containsCIS "JAEUAWAAgACgAWw" OR TgtProcCmdLine containsCIS "aQBlAHgAIAAoAFsA" OR TgtProcCmdLine containsCIS "kAZQB4ACAAKABbA" OR TgtProcCmdLine containsCIS "pAGUAeAAgACgAWw" OR TgtProcCmdLine containsCIS "aQBlAHgAIAAoAE4AZQB3A" OR TgtProcCmdLine containsCIS "kAZQB4ACAAKABOAGUAdw" OR TgtProcCmdLine containsCIS "pAGUAeAAgACgATgBlAHcA" OR TgtProcCmdLine containsCIS "SQBFAFgAIAAoAE4AZQB3A" OR TgtProcCmdLine containsCIS "kARQBYACAAKABOAGUAdw" OR TgtProcCmdLine containsCIS "JAEUAWAAgACgATgBlAHcA")))

```