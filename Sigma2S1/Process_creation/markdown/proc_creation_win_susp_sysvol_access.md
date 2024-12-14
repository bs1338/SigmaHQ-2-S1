# proc_creation_win_susp_sysvol_access

## Title
Suspicious SYSVOL Domain Group Policy Access

## ID
05f3c945-dcc8-4393-9f3d-af65077a8f86

## Author
Markus Neis, Jonhnathan Ribeiro, oscd.community

## Date
2018-04-09

## Tags
attack.credential-access, attack.t1552.006

## Description
Detects Access to Domain Group Policies stored in SYSVOL

## References
https://adsecurity.org/?p=2288
https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\SYSVOL\" AND TgtProcCmdLine containsCIS "\policies\"))

```