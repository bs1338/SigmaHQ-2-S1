# proc_creation_win_uac_bypass_pkgmgr_dism

## Title
UAC Bypass Using PkgMgr and DISM

## ID
a743ceba-c771-4d75-97eb-8a90f7f4844c

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-23

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using pkgmgr.exe and dism.exe (UACMe 23)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\dism.exe" AND (TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288")) AND SrcProcImagePath endswithCIS "\pkgmgr.exe"))

```