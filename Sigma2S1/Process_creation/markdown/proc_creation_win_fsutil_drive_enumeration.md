# proc_creation_win_fsutil_drive_enumeration

## Title
Fsutil Drive Enumeration

## ID
63de06b9-a385-40b5-8b32-73f2b9ef84b6

## Author
Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'

## Date
2022-03-29

## Tags
attack.discovery, attack.t1120

## Description
Attackers may leverage fsutil to enumerated connected drives.

## References
Turla has used fsutil fsinfo drives to list connected drives.
https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/discovery_peripheral_device.toml

## False Positives
Certain software or administrative tasks may trigger false positives.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "drives" AND TgtProcImagePath endswithCIS "\fsutil.exe"))

```