# file_event_win_sysinternals_psexec_service

## Title
PsExec Service File Creation

## ID
259e5a6a-b8d2-4c38-86e2-26c5e651361d

## Author
Thomas Patzke

## Date
2017-06-12

## Tags
attack.execution, attack.t1569.002, attack.s0029

## Description
Detects default PsExec service filename which indicates PsExec service installation and execution

## References
https://www.jpcert.or.jp/english/pub/sr/ir_research.html
https://jpcertcc.github.io/ToolAnalysisResultSheet

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "\PSEXESVC.exe")

```