# proc_creation_win_hktl_sharpwsus_wsuspendu_execution

## Title
HackTool - SharpWSUS/WSUSpendu Execution

## ID
b0ce780f-10bd-496d-9067-066d23dc3aa5

## Author
@Kostastsale, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-07

## Tags
attack.execution, attack.lateral-movement, attack.t1210

## Description
Detects the execution of SharpWSUS or WSUSpendu, utilities that allow for lateral movement through WSUS.
Windows Server Update Services (WSUS) is a critical component of Windows systems and is frequently configured in a way that allows an attacker to circumvent internal networking limitations.


## References
https://labs.nettitude.com/blog/introducing-sharpwsus/
https://github.com/nettitude/SharpWSUS
https://web.archive.org/web/20210512154016/https://github.com/AlsidOfficial/WSUSpendu/blob/master/WSUSpendu.ps1

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -Inject " AND (TgtProcCmdLine containsCIS " -PayloadArgs " OR TgtProcCmdLine containsCIS " -PayloadFile ")) OR ((TgtProcCmdLine containsCIS " approve " OR TgtProcCmdLine containsCIS " create " OR TgtProcCmdLine containsCIS " check " OR TgtProcCmdLine containsCIS " delete ") AND (TgtProcCmdLine containsCIS " /payload:" OR TgtProcCmdLine containsCIS " /payload=" OR TgtProcCmdLine containsCIS " /updateid:" OR TgtProcCmdLine containsCIS " /updateid="))))

```