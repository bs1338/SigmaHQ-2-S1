# file_event_win_rdp_file_susp_creation

## Title
.RDP File Created By Uncommon Application

## ID
fccfb43e-09a7-4bd2-8b37-a5a7df33386d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-18

## Tags
attack.defense-evasion

## Description
Detects creation of a file with an ".rdp" extension by an application that doesn't commonly create such files.


## References
https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/
https://web.archive.org/web/20230726144748/https://blog.thickmints.dev/mintsights/detecting-rogue-rdp/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\brave.exe" OR SrcProcImagePath endswithCIS "\CCleaner Browser\Application\CCleanerBrowser.exe" OR SrcProcImagePath endswithCIS "\chromium.exe" OR SrcProcImagePath endswithCIS "\firefox.exe" OR SrcProcImagePath endswithCIS "\Google\Chrome\Application\chrome.exe" OR SrcProcImagePath endswithCIS "\iexplore.exe" OR SrcProcImagePath endswithCIS "\microsoftedge.exe" OR SrcProcImagePath endswithCIS "\msedge.exe" OR SrcProcImagePath endswithCIS "\Opera.exe" OR SrcProcImagePath endswithCIS "\Vivaldi.exe" OR SrcProcImagePath endswithCIS "\Whale.exe" OR SrcProcImagePath endswithCIS "\olk.exe" OR SrcProcImagePath endswithCIS "\Outlook.exe" OR SrcProcImagePath endswithCIS "\RuntimeBroker.exe" OR SrcProcImagePath endswithCIS "\Thunderbird.exe" OR SrcProcImagePath endswithCIS "\Discord.exe" OR SrcProcImagePath endswithCIS "\Keybase.exe" OR SrcProcImagePath endswithCIS "\msteams.exe" OR SrcProcImagePath endswithCIS "\Slack.exe" OR SrcProcImagePath endswithCIS "\teams.exe") AND TgtFilePath endswithCIS ".rdp"))

```