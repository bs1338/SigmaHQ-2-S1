# file_event_win_bloodhound_collection

## Title
BloodHound Collection Files

## ID
02773bed-83bf-469f-b7ff-e676e7d78bab

## Author
C.J. May

## Date
2022-08-09

## Tags
attack.discovery, attack.t1087.001, attack.t1087.002, attack.t1482, attack.t1069.001, attack.t1069.002, attack.execution, attack.t1059.001

## Description
Detects default file names outputted by the BloodHound collection tool SharpHound

## References
https://academy.hackthebox.com/course/preview/active-directory-bloodhound/bloodhound--data-collection

## False Positives
Some false positives may arise in some environment and this may require some tuning. Add additional filters or reduce level depending on the level of noise

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "BloodHound.zip" OR TgtFilePath endswithCIS "_computers.json" OR TgtFilePath endswithCIS "_containers.json" OR TgtFilePath endswithCIS "_domains.json" OR TgtFilePath endswithCIS "_gpos.json" OR TgtFilePath endswithCIS "_groups.json" OR TgtFilePath endswithCIS "_ous.json" OR TgtFilePath endswithCIS "_users.json") AND (NOT (SrcProcImagePath endswithCIS "\svchost.exe" AND TgtFilePath endswithCIS "\pocket_containers.json" AND TgtFilePath startswithCIS "C:\Program Files\WindowsApps\Microsoft."))))

```