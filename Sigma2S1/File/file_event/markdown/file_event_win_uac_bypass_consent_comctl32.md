# file_event_win_uac_bypass_consent_comctl32

## Title
UAC Bypass Using Consent and Comctl32 - File

## ID
62ed5b55-f991-406a-85d9-e8e8fdf18789

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-23

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\comctl32.dll" AND TgtFilePath startswithCIS "C:\Windows\System32\consent.exe.@"))

```