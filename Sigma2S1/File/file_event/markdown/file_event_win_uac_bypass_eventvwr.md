# file_event_win_uac_bypass_eventvwr

## Title
UAC Bypass Using EventVwr

## ID
63e4f530-65dc-49cc-8f80-ccfa95c69d43

## Author
Antonio Cocomazzi (idea), Florian Roth (Nextron Systems)

## Date
2022-04-27

## Tags
attack.defense-evasion, attack.privilege-escalation

## Description
Detects the pattern of a UAC bypass using Windows Event Viewer

## References
https://twitter.com/orange_8361/status/1518970259868626944?s=20&t=RFXqZjtA7tWM3HxqEH78Aw
https://twitter.com/splinter_code/status/1519075134296006662?s=12&t=DLUXH86WtcmG_AZ5gY3C6g
https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/#execute

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\Microsoft\Event Viewer\RecentViews" OR TgtFilePath endswithCIS "\Microsoft\EventV~1\RecentViews") AND (NOT (SrcProcImagePath startswithCIS "C:\Windows\System32\" OR SrcProcImagePath startswithCIS "C:\Windows\SysWOW64\"))))

```