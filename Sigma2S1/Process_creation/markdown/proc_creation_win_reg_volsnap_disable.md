# proc_creation_win_reg_volsnap_disable

## Title
Disabled Volume Snapshots

## ID
dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a

## Author
Florian Roth (Nextron Systems)

## Date
2021-01-28

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects commands that temporarily turn off Volume Snapshots

## References
https://twitter.com/0gtweet/status/1354766164166115331

## False Positives
Legitimate administration

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\Services\VSS\Diag" AND TgtProcCmdLine containsCIS "/d Disabled"))

```