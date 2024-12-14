# proc_creation_win_powershell_cmdline_reversed_strings

## Title
Potential PowerShell Obfuscation Via Reversed Commands

## ID
b6b49cd1-34d6-4ead-b1bf-176e9edba9a4

## Author
Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton

## Date
2020-10-11

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects the presence of reversed PowerShell commands in the CommandLine. This is often used as a method of obfuscation by attackers

## References
https://2019.offzone.moscow/ru/report/hunting-for-powershell-abuses/
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=66

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "hctac" OR TgtProcCmdLine containsCIS "kaerb" OR TgtProcCmdLine containsCIS "dnammoc" OR TgtProcCmdLine containsCIS "ekovn" OR TgtProcCmdLine containsCIS "eliFd" OR TgtProcCmdLine containsCIS "rahc" OR TgtProcCmdLine containsCIS "etirw" OR TgtProcCmdLine containsCIS "golon" OR TgtProcCmdLine containsCIS "tninon" OR TgtProcCmdLine containsCIS "eddih" OR TgtProcCmdLine containsCIS "tpircS" OR TgtProcCmdLine containsCIS "ssecorp" OR TgtProcCmdLine containsCIS "llehsrewop" OR TgtProcCmdLine containsCIS "esnopser" OR TgtProcCmdLine containsCIS "daolnwod" OR TgtProcCmdLine containsCIS "tneilCbeW" OR TgtProcCmdLine containsCIS "tneilc" OR TgtProcCmdLine containsCIS "ptth" OR TgtProcCmdLine containsCIS "elifotevas" OR TgtProcCmdLine containsCIS "46esab" OR TgtProcCmdLine containsCIS "htaPpmeTteG" OR TgtProcCmdLine containsCIS "tcejbO" OR TgtProcCmdLine containsCIS "maerts" OR TgtProcCmdLine containsCIS "hcaerof" OR TgtProcCmdLine containsCIS "retupmoc") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")) AND (NOT (TgtProcCmdLine containsCIS " -EncodedCommand " OR TgtProcCmdLine containsCIS " -enc "))))

```