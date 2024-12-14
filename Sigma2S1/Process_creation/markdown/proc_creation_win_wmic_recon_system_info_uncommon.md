# proc_creation_win_wmic_recon_system_info_uncommon

## Title
Uncommon System Information Discovery Via Wmic.EXE

## ID
9d5a1274-922a-49d0-87f3-8c653483b909

## Author
TropChaud

## Date
2023-01-26

## Tags
attack.discovery, attack.t1082

## Description
Detects the use of the WMI command-line (WMIC) utility to identify and display various system information,
including OS, CPU, GPU, and disk drive names; memory capacity; display resolution; and baseboard, BIOS,
and GPU driver products/versions.
 Some of these commands were used by Aurora Stealer in late 2022/early 2023.


## References
https://github.com/redcanaryco/atomic-red-team/blob/a2ccd19c37d0278b4ffa8583add3cf52060a5418/atomics/T1082/T1082.md#atomic-test-25---system-information-discovery-with-wmic
https://nwgat.ninja/getting-system-information-with-wmic-on-windows/
https://blog.sekoia.io/aurora-a-rising-stealer-flying-under-the-radar
https://blog.cyble.com/2023/01/18/aurora-a-stealer-using-shapeshifting-tactics/
https://app.any.run/tasks/a6aa0057-82ec-451f-8f99-55650ca537da/
https://www.virustotal.com/gui/file/d6f6bc10ae0e634ed4301d584f61418cee18e5d58ad9af72f8aa552dc4aaeca3/behavior

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "LOGICALDISK get Name,Size,FreeSpace" OR TgtProcCmdLine containsCIS "os get Caption,OSArchitecture,Version") AND (TgtProcDisplayName = "WMI Commandline Utility" OR TgtProcImagePath endswithCIS "\WMIC.exe")))

```