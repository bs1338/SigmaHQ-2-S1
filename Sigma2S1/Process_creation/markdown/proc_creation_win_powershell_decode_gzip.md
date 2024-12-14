# proc_creation_win_powershell_decode_gzip

## Title
Gzip Archive Decode Via PowerShell

## ID
98767d61-b2e8-4d71-b661-e36783ee24c1

## Author
Hieu Tran

## Date
2023-03-13

## Tags
attack.command-and-control, attack.t1132.001

## Description
Detects attempts of decoding encoded Gzip archives via PowerShell.

## References
https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution

## False Positives
Legitimate administrative scripts may use this functionality. Use "ParentImage" in combination with the script names and allowed users and applications to filter legitimate executions

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "GZipStream" AND TgtProcCmdLine containsCIS "::Decompress"))

```