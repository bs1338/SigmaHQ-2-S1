# proc_creation_win_powershell_encoding_patterns

## Title
Potential Encoded PowerShell Patterns In CommandLine

## ID
cdf05894-89e7-4ead-b2b0-0a5f97a90f2f

## Author
Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton

## Date
2020-10-11

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects specific combinations of encoding methods in PowerShell via the commandline

## References
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=65

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (((TgtProcCmdLine containsCIS "ToInt" OR TgtProcCmdLine containsCIS "ToDecimal" OR TgtProcCmdLine containsCIS "ToByte" OR TgtProcCmdLine containsCIS "ToUint" OR TgtProcCmdLine containsCIS "ToSingle" OR TgtProcCmdLine containsCIS "ToSByte") AND (TgtProcCmdLine containsCIS "ToChar" OR TgtProcCmdLine containsCIS "ToString" OR TgtProcCmdLine containsCIS "String")) OR ((TgtProcCmdLine containsCIS "char" AND TgtProcCmdLine containsCIS "join") OR (TgtProcCmdLine containsCIS "split" AND TgtProcCmdLine containsCIS "join")))))

```