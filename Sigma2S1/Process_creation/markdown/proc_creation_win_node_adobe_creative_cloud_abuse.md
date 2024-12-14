# proc_creation_win_node_adobe_creative_cloud_abuse

## Title
Node Process Executions

## ID
df1f26d3-bea7-4700-9ea2-ad3e990cf90e

## Author
Max Altgelt (Nextron Systems)

## Date
2022-04-06

## Tags
attack.defense-evasion, attack.t1127, attack.t1059.007

## Description
Detects the execution of other scripts using the Node executable packaged with Adobe Creative Cloud

## References
https://twitter.com/mttaggart/status/1511804863293784064

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\Adobe Creative Cloud Experience\libs\node.exe" AND (NOT TgtProcCmdLine containsCIS "Adobe Creative Cloud Experience\js")))

```