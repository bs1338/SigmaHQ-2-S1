# proc_creation_win_uac_bypass_wsreset_integrity_level

## Title
UAC Bypass WSReset

## ID
89a9a0e0-f61a-42e5-8957-b1479565a658

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-23

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass via WSReset usable by default sysmon-config

## References
https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
https://github.com/hfiref0x/UACME
https://medium.com/falconforce/falconfriday-detecting-uac-bypasses-0xff16-86c2a9107abf

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\wsreset.exe" AND (TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288"))))

```