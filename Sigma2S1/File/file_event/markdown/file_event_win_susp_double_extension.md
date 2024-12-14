# file_event_win_susp_double_extension

## Title
Suspicious Double Extension Files

## ID
b4926b47-a9d7-434c-b3a0-adc3fa0bd13e

## Author
Nasreddine Bencherchali (Nextron Systems), frack113

## Date
2022-06-19

## Tags
attack.defense-evasion, attack.t1036.007

## Description
Detects dropped files with double extensions, which is often used by malware as a method to abuse the fact that Windows hide default extensions by default.

## References
https://www.crowdstrike.com/blog/meet-crowdstrikes-adversary-of-the-month-for-june-mustang-panda/
https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations
https://www.cybereason.com/blog/research/a-bazar-of-tricks-following-team9s-development-cycles
https://twitter.com/malwrhunterteam/status/1235135745611960321
https://twitter.com/luc4m/status/1073181154126254080

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS ".rar.exe" OR TgtFilePath endswithCIS ".zip.exe") OR ((TgtFilePath containsCIS ".doc." OR TgtFilePath containsCIS ".docx." OR TgtFilePath containsCIS ".jpg." OR TgtFilePath containsCIS ".pdf." OR TgtFilePath containsCIS ".ppt." OR TgtFilePath containsCIS ".pptx." OR TgtFilePath containsCIS ".xls." OR TgtFilePath containsCIS ".xlsx.") AND (TgtFilePath endswithCIS ".exe" OR TgtFilePath endswithCIS ".iso" OR TgtFilePath endswithCIS ".rar" OR TgtFilePath endswithCIS ".zip"))))

```