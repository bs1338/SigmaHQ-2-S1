# proc_creation_win_cmd_shadowcopy_access

## Title
Copy From VolumeShadowCopy Via Cmd.EXE

## ID
c73124a7-3e89-44a3-bdc1-25fe4df754b1

## Author
Max Altgelt (Nextron Systems), Tobias Michalski (Nextron Systems)

## Date
2021-08-09

## Tags
attack.impact, attack.t1490

## Description
Detects the execution of the builtin "copy" command that targets a shadow copy (sometimes used to copy registry hives that are in use)

## References
https://twitter.com/vxunderground/status/1423336151860002816?s=20
https://www.virustotal.com/gui/file/03e9b8c2e86d6db450e5eceec057d7e369ee2389b9daecaf06331a95410aa5f8/detection
https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/

## False Positives
Backup scenarios using the commandline

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "copy " AND TgtProcCmdLine containsCIS "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy"))

```