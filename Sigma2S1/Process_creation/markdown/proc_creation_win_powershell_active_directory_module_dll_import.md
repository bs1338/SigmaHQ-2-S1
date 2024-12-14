# proc_creation_win_powershell_active_directory_module_dll_import

## Title
Potential Active Directory Enumeration Using AD Module - ProcCreation

## ID
70bc5215-526f-4477-963c-a47a5c9ebd12

## Author
frack113

## Date
2023-01-22

## Tags
attack.reconnaissance, attack.discovery, attack.impact

## Description
Detects usage of the "Import-Module" cmdlet to load the "Microsoft.ActiveDirectory.Management.dl" DLL. Which is often used by attackers to perform AD enumeration.

## References
https://github.com/samratashok/ADModule
https://twitter.com/cyb3rops/status/1617108657166061568?s=20
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges

## False Positives
Legitimate use of the library for administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Import-Module " OR TgtProcCmdLine containsCIS "ipmo ") AND TgtProcCmdLine containsCIS "Microsoft.ActiveDirectory.Management.dll" AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```