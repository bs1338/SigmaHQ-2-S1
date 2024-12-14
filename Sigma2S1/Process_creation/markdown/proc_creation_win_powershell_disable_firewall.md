# proc_creation_win_powershell_disable_firewall

## Title
Windows Firewall Disabled via PowerShell

## ID
12f6b752-042d-483e-bf9c-915a6d06ad75

## Author
Tim Rauch, Elastic (idea)

## Date
2022-09-14

## Tags
attack.defense-evasion, attack.t1562

## Description
Detects attempts to disable the Windows Firewall using PowerShell

## References
https://www.elastic.co/guide/en/security/current/windows-firewall-disabled-via-powershell.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Set-NetFirewallProfile " AND TgtProcCmdLine containsCIS " -Enabled " AND TgtProcCmdLine containsCIS " False") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\powershell_ise.exe") AND (TgtProcCmdLine containsCIS " -All " OR TgtProcCmdLine containsCIS "Public" OR TgtProcCmdLine containsCIS "Domain" OR TgtProcCmdLine containsCIS "Private")))

```