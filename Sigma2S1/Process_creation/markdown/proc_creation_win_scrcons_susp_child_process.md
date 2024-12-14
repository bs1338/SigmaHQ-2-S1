# proc_creation_win_scrcons_susp_child_process

## Title
Script Event Consumer Spawning Process

## ID
f6d1dd2f-b8ce-40ca-bc23-062efb686b34

## Author
Sittikorn S

## Date
2021-06-21

## Tags
attack.execution, attack.t1047

## Description
Detects a suspicious child process of Script Event Consumer (scrcons.exe).

## References
https://redcanary.com/blog/child-processes/
https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/scrcons-exe-rare-child-process.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\svchost.exe" OR TgtProcImagePath endswithCIS "\dllhost.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\msbuild.exe") AND SrcProcImagePath endswithCIS "\scrcons.exe"))

```