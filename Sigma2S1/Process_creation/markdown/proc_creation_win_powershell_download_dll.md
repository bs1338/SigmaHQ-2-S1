# proc_creation_win_powershell_download_dll

## Title
Potential DLL File Download Via PowerShell Invoke-WebRequest

## ID
0f0450f3-8b47-441e-a31b-15a91dc243e2

## Author
Florian Roth (Nextron Systems), Hieu Tran

## Date
2023-03-13

## Tags
attack.command-and-control, attack.execution, attack.t1059.001, attack.t1105

## Description
Detects potential DLL files being downloaded using the PowerShell Invoke-WebRequest cmdlet

## References
https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Invoke-WebRequest " OR TgtProcCmdLine containsCIS "IWR ") AND (TgtProcCmdLine containsCIS "http" AND TgtProcCmdLine containsCIS "OutFile" AND TgtProcCmdLine containsCIS ".dll")))

```