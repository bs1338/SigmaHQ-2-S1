# proc_creation_win_powershell_snapins_hafnium

## Title
Exchange PowerShell Snap-Ins Usage

## ID
25676e10-2121-446e-80a4-71ff8506af47

## Author
FPT.EagleEye, Nasreddine Bencherchali (Nextron Systems)

## Date
2021-03-03

## Tags
attack.execution, attack.t1059.001, attack.collection, attack.t1114

## Description
Detects adding and using Exchange PowerShell snap-ins to export mailbox data. As seen used by HAFNIUM and APT27

## References
https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
https://www.intrinsec.com/apt27-analysis/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Add-PSSnapin" AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (TgtProcCmdLine containsCIS "Microsoft.Exchange.Powershell.Snapin" OR TgtProcCmdLine containsCIS "Microsoft.Exchange.Management.PowerShell.SnapIn")) AND (NOT (TgtProcCmdLine containsCIS "$exserver=Get-ExchangeServer ([Environment]::MachineName) -ErrorVariable exerr 2> $null" AND SrcProcImagePath = "C:\Windows\System32\msiexec.exe"))))

```