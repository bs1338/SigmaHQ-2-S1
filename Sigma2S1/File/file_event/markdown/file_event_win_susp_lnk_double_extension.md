# file_event_win_susp_lnk_double_extension

## Title
Suspicious LNK Double Extension File Created

## ID
3215aa19-f060-4332-86d5-5602511f3ca8

## Author
Nasreddine Bencherchali (Nextron Systems), frack113

## Date
2022-11-07

## Tags
attack.defense-evasion, attack.t1036.007

## Description
Detects the creation of files with an "LNK" as a second extension. This is sometimes used by malware as a method to abuse the fact that Windows hides the "LNK" extension by default.


## References
https://www.crowdstrike.com/blog/meet-crowdstrikes-adversary-of-the-month-for-june-mustang-panda/
https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations
https://www.cybereason.com/blog/research/a-bazar-of-tricks-following-team9s-development-cycles
https://twitter.com/malwrhunterteam/status/1235135745611960321
https://twitter.com/luc4m/status/1073181154126254080

## False Positives
Some tuning is required for other general purpose directories of third party apps

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (((TgtFilePath containsCIS ".doc." OR TgtFilePath containsCIS ".docx." OR TgtFilePath containsCIS ".jpg." OR TgtFilePath containsCIS ".pdf." OR TgtFilePath containsCIS ".ppt." OR TgtFilePath containsCIS ".pptx." OR TgtFilePath containsCIS ".xls." OR TgtFilePath containsCIS ".xlsx.") AND TgtFilePath endswithCIS ".lnk") AND (NOT TgtFilePath containsCIS "\AppData\Roaming\Microsoft\Windows\Recent\") AND (NOT ((SrcProcImagePath endswithCIS "\excel.exe" AND TgtFilePath containsCIS "\AppData\Roaming\Microsoft\Excel") OR (SrcProcImagePath endswithCIS "\powerpnt.exe" AND TgtFilePath containsCIS "\AppData\Roaming\Microsoft\PowerPoint") OR ((SrcProcImagePath endswithCIS "\excel.exe" OR SrcProcImagePath endswithCIS "\powerpnt.exe" OR SrcProcImagePath endswithCIS "\winword.exe") AND TgtFilePath containsCIS "\AppData\Roaming\Microsoft\Office\Recent\") OR (SrcProcImagePath endswithCIS "\winword.exe" AND TgtFilePath containsCIS "\AppData\Roaming\Microsoft\Word")))))

```