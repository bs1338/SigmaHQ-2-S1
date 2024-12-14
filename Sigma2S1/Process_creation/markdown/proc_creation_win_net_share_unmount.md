# proc_creation_win_net_share_unmount

## Title
Unmount Share Via Net.EXE

## ID
cb7c4a03-2871-43c0-9bbb-18bbdb079896

## Author
oscd.community, @redcanary, Zach Stanford @svch0st

## Date
2020-10-08

## Tags
attack.defense-evasion, attack.t1070.005

## Description
Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.005/T1070.005.md

## False Positives
Administrators or Power users may remove their shares via cmd line

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "share" AND TgtProcCmdLine containsCIS "/delete") AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")))

```