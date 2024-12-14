# proc_creation_win_sysinternals_psloglist

## Title
Suspicious Use of PsLogList

## ID
aae1243f-d8af-40d8-ab20-33fc6d0c55bc

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2021-12-18

## Tags
attack.discovery, attack.t1087, attack.t1087.001, attack.t1087.002

## Description
Detects usage of the PsLogList utility to dump event log in order to extract admin accounts and perform account discovery or delete events logs

## References
https://research.nccgroup.com/2021/01/12/abusing-cloud-services-to-fly-under-the-radar/
https://www.cybereason.com/blog/deadringer-exposing-chinese-threat-actors-targeting-major-telcos
https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Sysinternals/PsLogList
https://twitter.com/EricaZelic/status/1614075109827874817

## False Positives
Another tool that uses the command line switches of PsLogList
Legitimate use of PsLogList by an administrator

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " security" OR TgtProcCmdLine containsCIS " application" OR TgtProcCmdLine containsCIS " system") AND (TgtProcCmdLine containsCIS " -d" OR TgtProcCmdLine containsCIS " /d" OR TgtProcCmdLine containsCIS " â€“d" OR TgtProcCmdLine containsCIS " â€”d" OR TgtProcCmdLine containsCIS " â€•d" OR TgtProcCmdLine containsCIS " -x" OR TgtProcCmdLine containsCIS " /x" OR TgtProcCmdLine containsCIS " â€“x" OR TgtProcCmdLine containsCIS " â€”x" OR TgtProcCmdLine containsCIS " â€•x" OR TgtProcCmdLine containsCIS " -s" OR TgtProcCmdLine containsCIS " /s" OR TgtProcCmdLine containsCIS " â€“s" OR TgtProcCmdLine containsCIS " â€”s" OR TgtProcCmdLine containsCIS " â€•s" OR TgtProcCmdLine containsCIS " -c" OR TgtProcCmdLine containsCIS " /c" OR TgtProcCmdLine containsCIS " â€“c" OR TgtProcCmdLine containsCIS " â€”c" OR TgtProcCmdLine containsCIS " â€•c" OR TgtProcCmdLine containsCIS " -g" OR TgtProcCmdLine containsCIS " /g" OR TgtProcCmdLine containsCIS " â€“g" OR TgtProcCmdLine containsCIS " â€”g" OR TgtProcCmdLine containsCIS " â€•g") AND (TgtProcImagePath endswithCIS "\psloglist.exe" OR TgtProcImagePath endswithCIS "\psloglist64.exe")))

```