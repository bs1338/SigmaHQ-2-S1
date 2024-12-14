# proc_creation_win_susp_commandline_path_traversal_evasion

## Title
Potential Command Line Path Traversal Evasion Attempt

## ID
1327381e-6ab0-4f38-b583-4c1b8346a56b

## Author
Christian Burkard (Nextron Systems)

## Date
2021-10-26

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects potential evasion or obfuscation attempts using bogus path traversal via the commandline

## References
https://twitter.com/hexacorn/status/1448037865435320323
https://twitter.com/Gal_B1t/status/1062971006078345217

## False Positives
Google Drive
Citrix

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcCmdLine containsCIS "\..\Windows\" OR TgtProcCmdLine containsCIS "\..\System32\" OR TgtProcCmdLine containsCIS "\..\..\") AND TgtProcImagePath containsCIS "\Windows\") OR TgtProcCmdLine containsCIS ".exe\..\") AND (NOT (TgtProcCmdLine containsCIS "\Citrix\Virtual Smart Card\Citrix.Authentication.VirtualSmartcard.Launcher.exe\..\" OR TgtProcCmdLine containsCIS "\Google\Drive\googledrivesync.exe\..\"))))

```