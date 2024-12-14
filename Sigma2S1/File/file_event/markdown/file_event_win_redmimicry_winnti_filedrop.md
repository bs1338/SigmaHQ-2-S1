# file_event_win_redmimicry_winnti_filedrop

## Title
Potential Winnti Dropper Activity

## ID
130c9e58-28ac-4f83-8574-0a4cc913b97e

## Author
Alexander Rausch

## Date
2020-06-24

## Tags
attack.defense-evasion, attack.t1027

## Description
Detects files dropped by Winnti as described in RedMimicry Winnti playbook

## References
https://redmimicry.com/posts/redmimicry-winnti/#dropper

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\gthread-3.6.dll" OR TgtFilePath endswithCIS "\sigcmm-2.4.dll" OR TgtFilePath endswithCIS "\Windows\Temp\tmp.bat"))

```