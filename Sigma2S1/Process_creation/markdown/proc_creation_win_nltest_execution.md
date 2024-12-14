# proc_creation_win_nltest_execution

## Title
Nltest.EXE Execution

## ID
903076ff-f442-475a-b667-4f246bcc203b

## Author
Arun Chauhan

## Date
2023-02-03

## Tags
attack.discovery, attack.t1016, attack.t1018, attack.t1482

## Description
Detects nltest commands that can be used for information discovery

## References
https://jpcertcc.github.io/ToolAnalysisResultSheet/details/nltest.htm

## False Positives
Legitimate administration activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\nltest.exe")

```