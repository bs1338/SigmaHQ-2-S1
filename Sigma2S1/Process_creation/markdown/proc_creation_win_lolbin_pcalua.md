# proc_creation_win_lolbin_pcalua

## Title
Use of Pcalua For Execution

## ID
0955e4e1-c281-4fb9-9ee1-5ee7b4b754d2

## Author
Nasreddine Bencherchali (Nextron Systems), E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community

## Date
2022-06-14

## Tags
attack.execution, attack.t1059

## Description
Detects execition of commands and binaries from the context of The program compatibility assistant (Pcalua.exe). This can be used as a LOLBIN in order to bypass application whitelisting.

## References
https://lolbas-project.github.io/lolbas/Binaries/Pcalua/
https://pentestlab.blog/2020/07/06/indirect-command-execution/

## False Positives
Legitimate use by a via a batch script or by an administrator.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -a" AND TgtProcImagePath endswithCIS "\pcalua.exe"))

```