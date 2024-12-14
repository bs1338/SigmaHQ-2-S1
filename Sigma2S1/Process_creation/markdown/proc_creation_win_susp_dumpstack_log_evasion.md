# proc_creation_win_susp_dumpstack_log_evasion

## Title
DumpStack.log Defender Evasion

## ID
4f647cfa-b598-4e12-ad69-c68dd16caef8

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-06

## Tags
attack.defense-evasion

## Description
Detects the use of the filename DumpStack.log to evade Microsoft Defender

## References
https://twitter.com/mrd0x/status/1479094189048713219

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\DumpStack.log" OR TgtProcCmdLine containsCIS " -o DumpStack.log"))

```