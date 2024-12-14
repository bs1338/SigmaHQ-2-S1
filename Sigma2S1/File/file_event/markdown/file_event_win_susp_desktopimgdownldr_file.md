# file_event_win_susp_desktopimgdownldr_file

## Title
Suspicious Desktopimgdownldr Target File

## ID
fc4f4817-0c53-4683-a4ee-b17a64bc1039

## Author
Florian Roth (Nextron Systems)

## Date
2020-07-03

## Tags
attack.command-and-control, attack.t1105

## Description
Detects a suspicious Microsoft desktopimgdownldr file creation that stores a file to a suspicious location or contains a file with a suspicious extension

## References
https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
https://twitter.com/SBousseaden/status/1278977301745741825

## False Positives
False positives depend on scripts and administrative tools used in the monitored environment

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\svchost.exe" AND TgtFilePath containsCIS "\Personalization\LockScreenImage\") AND (NOT TgtFilePath containsCIS "C:\Windows\") AND (NOT (TgtFilePath containsCIS ".jpg" OR TgtFilePath containsCIS ".jpeg" OR TgtFilePath containsCIS ".png"))))

```