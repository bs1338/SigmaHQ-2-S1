# file_event_win_sam_dump

## Title
Potential SAM Database Dump

## ID
4e87b8e2-2ee9-4b2a-a715-4727d297ece0

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-11

## Tags
attack.credential-access, attack.t1003.002

## Description
Detects the creation of files that look like exports of the local SAM (Security Account Manager)

## References
https://github.com/search?q=CVE-2021-36934
https://web.archive.org/web/20210725081645/https://github.com/cube0x0/CVE-2021-36934
https://www.google.com/search?q=%22reg.exe+save%22+sam
https://github.com/HuskyHacks/ShadowSteal
https://github.com/FireFart/hivenightmare

## False Positives
Rare cases of administrative activity

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\Temp\sam" OR TgtFilePath endswithCIS "\sam.sav" OR TgtFilePath endswithCIS "\Intel\sam" OR TgtFilePath endswithCIS "\sam.hive" OR TgtFilePath endswithCIS "\Perflogs\sam" OR TgtFilePath endswithCIS "\ProgramData\sam" OR TgtFilePath endswithCIS "\Users\Public\sam" OR TgtFilePath endswithCIS "\AppData\Local\sam" OR TgtFilePath endswithCIS "\AppData\Roaming\sam" OR TgtFilePath endswithCIS "_ShadowSteal.zip" OR TgtFilePath endswithCIS "\Documents\SAM.export" OR TgtFilePath endswithCIS ":\sam") OR (TgtFilePath containsCIS "\hive_sam_" OR TgtFilePath containsCIS "\sam.save" OR TgtFilePath containsCIS "\sam.export" OR TgtFilePath containsCIS "\~reg_sam.save" OR TgtFilePath containsCIS "\sam_backup" OR TgtFilePath containsCIS "\sam.bck" OR TgtFilePath containsCIS "\sam.backup")))

```