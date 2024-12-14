# proc_creation_win_java_susp_child_process_2

## Title
Shell Process Spawned by Java.EXE

## ID
dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0

## Author
Andreas Hunkeler (@Karneades), Nasreddine Bencherchali

## Date
2021-12-17

## Tags
attack.initial-access, attack.persistence, attack.privilege-escalation

## Description
Detects shell spawned from Java host process, which could be a sign of exploitation (e.g. log4j exploitation)

## References
https://web.archive.org/web/20231230220738/https://www.lunasec.io/docs/blog/log4j-zero-day/

## False Positives
Legitimate calls to system binaries
Company specific internal usage

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND SrcProcImagePath endswithCIS "\java.exe") AND (NOT (TgtProcCmdLine containsCIS "build" AND SrcProcImagePath containsCIS "build"))))

```