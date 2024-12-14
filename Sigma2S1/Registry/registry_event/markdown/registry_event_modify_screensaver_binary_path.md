# registry_event_modify_screensaver_binary_path

## Title
Path To Screensaver Binary Modified

## ID
67a6c006-3fbe-46a7-9074-2ba3b82c3000

## Author
Bartlomiej Czyz @bczyz1, oscd.community

## Date
2020-10-11

## Tags
attack.persistence, attack.privilege-escalation, attack.t1546.002

## Description
Detects value modification of registry key containing path to binary used as screensaver.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.002/T1546.002.md
https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf

## False Positives
Legitimate modification of screensaver

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "\Control Panel\Desktop\SCRNSAVE.EXE" AND (NOT (SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\explorer.exe"))))

```