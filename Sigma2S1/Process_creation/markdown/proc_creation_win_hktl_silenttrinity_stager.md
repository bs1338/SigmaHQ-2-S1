# proc_creation_win_hktl_silenttrinity_stager

## Title
HackTool - SILENTTRINITY Stager Execution

## ID
03552375-cc2c-4883-bbe4-7958d5a980be

## Author
Aleksey Potapov, oscd.community

## Date
2019-10-22

## Tags
attack.command-and-control, attack.t1071

## Description
Detects SILENTTRINITY stager use via PE metadata

## References
https://github.com/byt3bl33d3r/SILENTTRINITY

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcDisplayName containsCIS "st2stager")

```