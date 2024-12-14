# proc_creation_win_powershell_enable_susp_windows_optional_feature

## Title
Potential Suspicious Windows Feature Enabled - ProcCreation

## ID
c740d4cf-a1e9-41de-bb16-8a46a4f57918

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-29

## Tags
attack.defense-evasion

## Description
Detects usage of the built-in PowerShell cmdlet "Enable-WindowsOptionalFeature" used as a Deployment Image Servicing and Management tool.
Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images


## References
https://learn.microsoft.com/en-us/powershell/module/dism/enable-windowsoptionalfeature?view=windowsserver2022-ps
https://learn.microsoft.com/en-us/windows/win32/projfs/enabling-windows-projected-file-system
https://learn.microsoft.com/en-us/windows/wsl/install-on-server

## False Positives
Legitimate usage of the features listed in the rule.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Enable-WindowsOptionalFeature" AND TgtProcCmdLine containsCIS "-Online" AND TgtProcCmdLine containsCIS "-FeatureName") AND (TgtProcCmdLine containsCIS "TelnetServer" OR TgtProcCmdLine containsCIS "Internet-Explorer-Optional-amd64" OR TgtProcCmdLine containsCIS "TFTP" OR TgtProcCmdLine containsCIS "SMB1Protocol" OR TgtProcCmdLine containsCIS "Client-ProjFS" OR TgtProcCmdLine containsCIS "Microsoft-Windows-Subsystem-Linux")))

```