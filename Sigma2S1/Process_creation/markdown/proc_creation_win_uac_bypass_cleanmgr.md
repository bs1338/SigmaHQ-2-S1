# proc_creation_win_uac_bypass_cleanmgr

## Title
UAC Bypass Using Disk Cleanup

## ID
b697e69c-746f-4a86-9f59-7bfff8eab881

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-30

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using scheduled tasks and variable expansion of cleanmgr.exe (UACMe 34)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine endswithCIS "\"\system32\cleanmgr.exe /autoclean /d C:" AND (TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288")) AND SrcProcCmdLine = "C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule"))

```