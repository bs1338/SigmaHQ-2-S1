# proc_creation_win_pktmon_execution

## Title
PktMon.EXE Execution

## ID
f956c7c1-0f60-4bc5-b7d7-b39ab3c08908

## Author
frack113

## Date
2022-03-17

## Tags
attack.credential-access, attack.t1040

## Description
Detects execution of PktMon, a tool that captures network packets.

## References
https://lolbas-project.github.io/lolbas/Binaries/Pktmon/

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\pktmon.exe")

```