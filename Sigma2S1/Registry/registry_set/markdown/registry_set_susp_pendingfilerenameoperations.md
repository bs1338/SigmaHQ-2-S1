# registry_set_susp_pendingfilerenameoperations

## Title
Potential PendingFileRenameOperations Tampering

## ID
4eec988f-7bf0-49f1-8675-1e6a510b3a2a

## Author
frack113

## Date
2023-01-27

## Tags
attack.defense-evasion, attack.t1036.003

## Description
Detect changes to the "PendingFileRenameOperations" registry key from uncommon or suspicious images locations to stage currently used files for rename or deletion after reboot.


## References
https://any.run/report/3ecd4763ffc944fdc67a9027e459cd4f448b1a8d1b36147977afaf86bbf2a261/64b0ba45-e7ce-423b-9a1d-5b4ea59521e6
https://devblogs.microsoft.com/scripting/determine-pending-reboot-statuspowershell-style-part-1/
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960241(v=technet.10)?redirectedfrom=MSDN
https://www.trendmicro.com/en_us/research/21/j/purplefox-adds-new-backdoor-that-uses-websockets.html
https://www.trendmicro.com/en_us/research/19/i/purple-fox-fileless-malware-with-rookit-component-delivered-by-rig-exploit-kit-now-abuses-powershell.html

## False Positives
Installers and updaters may set currently in use files for rename or deletion after a reboot.

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((EventType = "SetValue" AND RegistryKeyPath containsCIS "\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations") AND ((SrcProcImagePath endswithCIS "\reg.exe" OR SrcProcImagePath endswithCIS "\regedit.exe") OR (SrcProcImagePath containsCIS "\AppData\Local\Temp\" OR SrcProcImagePath containsCIS "\Users\Public\"))))

```