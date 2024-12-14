# proc_creation_win_powershell_cmdline_convertto_securestring

## Title
ConvertTo-SecureString Cmdlet Usage Via CommandLine

## ID
74403157-20f5-415d-89a7-c505779585cf

## Author
Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton

## Date
2020-10-11

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects usage of the "ConvertTo-SecureString" cmdlet via the commandline. Which is fairly uncommon and could indicate potential suspicious activity

## References
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=65
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring?view=powershell-7.3#examples

## False Positives
Legitimate use to pass password to different powershell commands

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "ConvertTo-SecureString" AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```