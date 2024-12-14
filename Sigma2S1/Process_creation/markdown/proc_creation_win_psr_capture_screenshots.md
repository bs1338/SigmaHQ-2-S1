# proc_creation_win_psr_capture_screenshots

## Title
Screen Capture Activity Via Psr.EXE

## ID
2158f96f-43c2-43cb-952a-ab4580f32382

## Author
Beyu Denis, oscd.community

## Date
2019-10-12

## Tags
attack.collection, attack.t1113

## Description
Detects execution of Windows Problem Steps Recorder (psr.exe), a utility used to record the user screen and clicks.

## References
https://lolbas-project.github.io/lolbas/Binaries/Psr/
https://web.archive.org/web/20200229201156/https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493861893.pdf
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/start" OR TgtProcCmdLine containsCIS "-start") AND TgtProcImagePath endswithCIS "\Psr.exe"))

```