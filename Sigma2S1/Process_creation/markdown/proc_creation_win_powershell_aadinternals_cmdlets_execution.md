# proc_creation_win_powershell_aadinternals_cmdlets_execution

## Title
AADInternals PowerShell Cmdlets Execution - ProccessCreation

## ID
c86500e9-a645-4680-98d7-f882c70c1ea3

## Author
Austin Songer (@austinsonger), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-23

## Tags
attack.execution, attack.reconnaissance, attack.discovery, attack.credential-access, attack.impact

## Description
Detects ADDInternals Cmdlet execution. A tool for administering Azure AD and Office 365. Which can be abused by threat actors to attack Azure AD or Office 365.

## References
https://o365blog.com/aadinternals/
https://github.com/Gerenios/AADInternals

## False Positives
Legitimate use of the library for administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Add-AADInt" OR TgtProcCmdLine containsCIS "ConvertTo-AADInt" OR TgtProcCmdLine containsCIS "Disable-AADInt" OR TgtProcCmdLine containsCIS "Enable-AADInt" OR TgtProcCmdLine containsCIS "Export-AADInt" OR TgtProcCmdLine containsCIS "Get-AADInt" OR TgtProcCmdLine containsCIS "Grant-AADInt" OR TgtProcCmdLine containsCIS "Install-AADInt" OR TgtProcCmdLine containsCIS "Invoke-AADInt" OR TgtProcCmdLine containsCIS "Join-AADInt" OR TgtProcCmdLine containsCIS "New-AADInt" OR TgtProcCmdLine containsCIS "Open-AADInt" OR TgtProcCmdLine containsCIS "Read-AADInt" OR TgtProcCmdLine containsCIS "Register-AADInt" OR TgtProcCmdLine containsCIS "Remove-AADInt" OR TgtProcCmdLine containsCIS "Restore-AADInt" OR TgtProcCmdLine containsCIS "Search-AADInt" OR TgtProcCmdLine containsCIS "Send-AADInt" OR TgtProcCmdLine containsCIS "Set-AADInt" OR TgtProcCmdLine containsCIS "Start-AADInt" OR TgtProcCmdLine containsCIS "Update-AADInt") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```