# proc_creation_win_powershell_iex_patterns

## Title
Suspicious PowerShell IEX Execution Patterns

## ID
09576804-7a05-458e-a817-eb718ca91f54

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-03-24

## Tags
attack.execution, attack.t1059.001

## Description
Detects suspicious ways to run Invoke-Execution using IEX alias

## References
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2
https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## False Positives
Legitimate scripts that use IEX

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcCmdLine containsCIS " | iex;" OR TgtProcCmdLine containsCIS " | iex " OR TgtProcCmdLine containsCIS " | iex}" OR TgtProcCmdLine containsCIS " | IEX ;" OR TgtProcCmdLine containsCIS " | IEX -Error" OR TgtProcCmdLine containsCIS " | IEX (new" OR TgtProcCmdLine containsCIS ");IEX ") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")) AND (TgtProcCmdLine containsCIS "::FromBase64String" OR TgtProcCmdLine containsCIS ".GetString([System.Convert]::")) OR (TgtProcCmdLine containsCIS ")|iex;$" OR TgtProcCmdLine containsCIS ");iex($" OR TgtProcCmdLine containsCIS ");iex $" OR TgtProcCmdLine containsCIS " | IEX | " OR TgtProcCmdLine containsCIS " | iex\\"")))

```