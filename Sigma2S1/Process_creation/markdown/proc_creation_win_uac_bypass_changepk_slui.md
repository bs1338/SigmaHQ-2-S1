# proc_creation_win_uac_bypass_changepk_slui

## Title
UAC Bypass Using ChangePK and SLUI

## ID
503d581c-7df0-4bbe-b9be-5840c0ecc1fc

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-23

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects an UAC bypass that uses changepk.exe and slui.exe (UACMe 61)

## References
https://mattharr0ey.medium.com/privilege-escalation-uac-bypass-in-changepk-c40b92818d1b
https://github.com/hfiref0x/UACME
https://medium.com/falconforce/falconfriday-detecting-uac-bypasses-0xff16-86c2a9107abf

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\changepk.exe" AND (TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288")) AND SrcProcImagePath endswithCIS "\slui.exe"))

```