# proc_creation_win_susp_sensitive_file_access_shadowcopy

## Title
Sensitive File Access Via Volume Shadow Copy Backup

## ID
f57f8d16-1f39-4dcb-a604-6c73d9b54b3d

## Author
Max Altgelt (Nextron Systems), Tobias Michalski (Nextron Systems)

## Date
2021-08-09

## Tags
attack.impact, attack.t1490

## Description
Detects a command that accesses the VolumeShadowCopy in order to extract sensitive files such as the Security or SAM registry hives or the AD database (ntds.dit)


## References
https://twitter.com/vxunderground/status/1423336151860002816?s=20
https://www.virustotal.com/gui/file/03e9b8c2e86d6db450e5eceec057d7e369ee2389b9daecaf06331a95410aa5f8/detection
https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy" AND (TgtProcCmdLine containsCIS "\NTDS.dit" OR TgtProcCmdLine containsCIS "\SYSTEM" OR TgtProcCmdLine containsCIS "\SECURITY")))

```