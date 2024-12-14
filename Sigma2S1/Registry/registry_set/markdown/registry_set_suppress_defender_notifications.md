# registry_set_suppress_defender_notifications

## Title
Activate Suppression of Windows Security Center Notifications

## ID
0c93308a-3f1b-40a9-b649-57ea1a1c1d63

## Author
frack113

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1112

## Description
Detect set Notification_Suppress to 1 to disable the Windows security center notification

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration\Notification_Suppress"))

```