# proc_creation_win_uac_bypass_consent_comctl32

## Title
UAC Bypass Using Consent and Comctl32 - Process

## ID
1ca6bd18-0ba0-44ca-851c-92ed89a61085

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
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\werfault.exe" AND (TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288")) AND SrcProcImagePath endswithCIS "\consent.exe"))

```