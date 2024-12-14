# proc_creation_win_hktl_xordump

## Title
HackTool - XORDump Execution

## ID
66e563f9-1cbd-4a22-a957-d8b7c0f44372

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-28

## Tags
attack.defense-evasion, attack.t1036, attack.t1003.001

## Description
Detects suspicious use of XORDump process memory dumping utility

## References
https://github.com/audibleblink/xordump

## False Positives
Another tool that uses the command line switches of XORdump

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\xordump.exe" OR (TgtProcCmdLine containsCIS " -process lsass.exe " OR TgtProcCmdLine containsCIS " -m comsvcs " OR TgtProcCmdLine containsCIS " -m dbghelp " OR TgtProcCmdLine containsCIS " -m dbgcore ")))

```