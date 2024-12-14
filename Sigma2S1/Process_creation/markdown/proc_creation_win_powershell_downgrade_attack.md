# proc_creation_win_powershell_downgrade_attack

## Title
Potential PowerShell Downgrade Attack

## ID
b3512211-c67e-4707-bedc-66efc7848863

## Author
Harish Segar (rule)

## Date
2020-03-20

## Tags
attack.defense-evasion, attack.execution, attack.t1059.001

## Description
Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0

## References
http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/
https://github.com/r00t-3xp10it/hacking-material-books/blob/43cb1e1932c16ff1f58b755bc9ab6b096046853f/obfuscation/simple_obfuscation.md#bypass-or-avoid-amsi-by-version-downgrade-

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -version 2 " OR TgtProcCmdLine containsCIS " -versio 2 " OR TgtProcCmdLine containsCIS " -versi 2 " OR TgtProcCmdLine containsCIS " -vers 2 " OR TgtProcCmdLine containsCIS " -ver 2 " OR TgtProcCmdLine containsCIS " -ve 2 " OR TgtProcCmdLine containsCIS " -v 2 ") AND TgtProcImagePath endswithCIS "\powershell.exe"))

```