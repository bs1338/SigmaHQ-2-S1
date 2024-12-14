# proc_creation_win_hktl_sharpevtmute

## Title
HackTool - SharpEvtMute Execution

## ID
bedfc8ad-d1c7-4e37-a20e-e2b0dbee759c

## Author
Florian Roth (Nextron Systems)

## Date
2022-09-07

## Tags
attack.defense-evasion, attack.t1562.002

## Description
Detects the use of SharpEvtHook, a tool that tampers with the Windows event logs

## References
https://github.com/bats3c/EvtMute

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\SharpEvtMute.exe" OR TgtProcDisplayName = "SharpEvtMute" OR (TgtProcCmdLine containsCIS "--Filter \"rule " OR TgtProcCmdLine containsCIS "--Encoded --Filter \\"")))

```