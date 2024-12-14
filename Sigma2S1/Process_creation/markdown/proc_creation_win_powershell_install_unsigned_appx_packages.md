# proc_creation_win_powershell_install_unsigned_appx_packages

## Title
Unsigned AppX Installation Attempt Using Add-AppxPackage

## ID
37651c2a-42cd-4a69-ae0d-22a4349aa04a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-31

## Tags
attack.persistence, attack.defense-evasion

## Description
Detects usage of the "Add-AppxPackage" or it's alias "Add-AppPackage" to install unsigned AppX packages

## References
https://learn.microsoft.com/en-us/windows/msix/package/unsigned-package
https://twitter.com/WindowsDocs/status/1620078135080325122

## False Positives
Installation of unsigned packages for testing purposes

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Add-AppPackage " OR TgtProcCmdLine containsCIS "Add-AppxPackage ") AND TgtProcCmdLine containsCIS " -AllowUnsigned" AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```