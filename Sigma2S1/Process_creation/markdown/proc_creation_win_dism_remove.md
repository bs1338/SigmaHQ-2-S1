# proc_creation_win_dism_remove

## Title
Dism Remove Online Package

## ID
43e32da2-fdd0-4156-90de-50dfd62636f9

## Author
frack113

## Date
2022-01-16

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Deployment Image Servicing and Management tool. DISM is used to enumerate, install, uninstall, configure, and update features and packages in Windows images

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md#atomic-test-26---disable-windows-defender-with-dism
https://www.trendmicro.com/en_us/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver-to-kill-antivirus.html

## False Positives
Legitimate script

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "/Online" AND TgtProcCmdLine containsCIS "/Disable-Feature") AND TgtProcImagePath endswithCIS "\Dism.exe") OR (TgtProcImagePath endswithCIS "\DismHost.exe" AND (SrcProcCmdLine containsCIS "/Online" AND SrcProcCmdLine containsCIS "/Disable-Feature"))))

```