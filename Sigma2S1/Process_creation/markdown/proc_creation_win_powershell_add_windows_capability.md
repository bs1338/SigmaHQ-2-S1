# proc_creation_win_powershell_add_windows_capability

## Title
Add Windows Capability Via PowerShell Cmdlet

## ID
b36d01a3-ddaf-4804-be18-18a6247adfcd

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-22

## Tags
attack.execution

## Description
Detects usage of the "Add-WindowsCapability" cmdlet to add Windows capabilities. Notable capabilities could be "OpenSSH" and others.

## References
https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?tabs=powershell
https://www.virustotal.com/gui/file/af1c82237b6e5a3a7cdbad82cc498d298c67845d92971bada450023d1335e267/content

## False Positives
Legitimate usage of the capabilities by administrators or users. Add additional filters accordingly.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "OpenSSH." AND TgtProcCmdLine containsCIS "Add-WindowsCapability" AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```