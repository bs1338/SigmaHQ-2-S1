# proc_creation_win_pua_radmin

## Title
PUA - Radmin Viewer Utility Execution

## ID
5817e76f-4804-41e6-8f1d-5fa0b3ecae2d

## Author
frack113

## Date
2022-01-22

## Tags
attack.execution, attack.lateral-movement, attack.t1072

## Description
Detects the execution of Radmin which can be abused by an adversary to remotely control Windows machines

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1072/T1072.md
https://www.radmin.fr/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcDisplayName In Contains AnyCase ("Radmin Viewer","Radmin Viewer")))

```