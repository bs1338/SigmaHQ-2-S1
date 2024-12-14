# file_event_win_hktl_quarkspw_filedump

## Title
HackTool - QuarksPwDump Dump File

## ID
847def9e-924d-4e90-b7c4-5f581395a2b4

## Author
Florian Roth (Nextron Systems)

## Date
2018-02-10

## Tags
attack.credential-access, attack.t1003.002

## Description
Detects a dump file written by QuarksPwDump password dumper

## References
https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS "\AppData\Local\Temp\SAM-" AND TgtFilePath containsCIS ".dmp"))

```