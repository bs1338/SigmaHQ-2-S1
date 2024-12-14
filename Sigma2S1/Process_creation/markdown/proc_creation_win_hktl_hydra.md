# proc_creation_win_hktl_hydra

## Title
HackTool - Hydra Password Bruteforce Execution

## ID
aaafa146-074c-11eb-adc1-0242ac120002

## Author
Vasiliy Burov

## Date
2020-10-05

## Tags
attack.credential-access, attack.t1110, attack.t1110.001

## Description
Detects command line parameters used by Hydra password guessing hack tool

## References
https://github.com/vanhauser-thc/thc-hydra

## False Positives
Software that uses the caret encased keywords PASS and USER in its command line

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "^USER^" OR TgtProcCmdLine containsCIS "^PASS^") AND (TgtProcCmdLine containsCIS "-u " AND TgtProcCmdLine containsCIS "-p ")))

```