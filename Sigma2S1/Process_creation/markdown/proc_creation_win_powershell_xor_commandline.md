# proc_creation_win_powershell_xor_commandline

## Title
Suspicious XOR Encoded PowerShell Command

## ID
bb780e0c-16cf-4383-8383-1e5471db6cf9

## Author
Sami Ruohonen, Harish Segar, Tim Shelton, Teymur Kheirkhabarov, Vasiliy Burov, oscd.community, Nasreddine Bencherchali

## Date
2018-09-05

## Tags
attack.defense-evasion, attack.execution, attack.t1059.001, attack.t1140, attack.t1027

## Description
Detects presence of a potentially xor encoded powershell command

## References
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=65
https://redcanary.com/blog/yellow-cockatoo/
https://zero2auto.com/2020/05/19/netwalker-re/
https://mez0.cc/posts/cobaltstrike-powershell-exec/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "ForEach" OR TgtProcCmdLine containsCIS "for(" OR TgtProcCmdLine containsCIS "for " OR TgtProcCmdLine containsCIS "-join " OR TgtProcCmdLine containsCIS "-join'" OR TgtProcCmdLine containsCIS "-join\"" OR TgtProcCmdLine containsCIS "-join`" OR TgtProcCmdLine containsCIS "::Join" OR TgtProcCmdLine containsCIS "[char]") AND TgtProcCmdLine containsCIS "bxor" AND ((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") OR TgtProcDisplayName = "Windows PowerShell" OR TgtProcDisplayName = "PowerShell Core 6")))

```