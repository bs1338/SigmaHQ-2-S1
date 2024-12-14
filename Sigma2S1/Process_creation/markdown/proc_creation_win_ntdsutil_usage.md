# proc_creation_win_ntdsutil_usage

## Title
Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)

## ID
2afafd61-6aae-4df4-baed-139fa1f4c345

## Author
Thomas Patzke

## Date
2019-01-16

## Tags
attack.credential-access, attack.t1003.003

## Description
Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)

## References
https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm

## False Positives
NTDS maintenance

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\ntdsutil.exe")

```