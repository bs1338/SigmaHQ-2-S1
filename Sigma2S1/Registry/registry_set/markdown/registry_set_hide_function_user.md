# registry_set_hide_function_user

## Title
Registry Hide Function from User

## ID
5a93eb65-dffa-4543-b761-94aa60098fb6

## Author
frack113

## Date
2022-03-18

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects registry modifications that hide internal tools or functions from the user (malware like Agent Tesla, Hermetic Wiper uses this technique)

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.001/T1564.001.md

## False Positives
Legitimate admin script

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowInfoTip" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowCompColor")) OR (RegistryValue = "DWORD (0x00000001)" AND (RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\HideClock" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\HideSCAHealth" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\HideSCANetwork" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\HideSCAPower" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\HideSCAVolume"))))

```