# proc_creation_win_wusa_cab_files_extraction_from_susp_paths

## Title
Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths

## ID
c74c0390-3e20-41fd-a69a-128f0275a5ea

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-05

## Tags
attack.execution

## Description
Detects the execution of the "wusa.exe" (Windows Update Standalone Installer) utility to extract ".cab" files using the "/extract" argument from potentially suspicious paths.


## References
https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
https://www.echotrail.io/insights/search/wusa.exe/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ":\PerfLogs\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\Appdata\Local\Temp\") AND (TgtProcCmdLine containsCIS "/extract:" AND TgtProcImagePath endswithCIS "\wusa.exe")))

```