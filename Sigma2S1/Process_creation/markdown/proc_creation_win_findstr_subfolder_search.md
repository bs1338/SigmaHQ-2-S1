# proc_creation_win_findstr_subfolder_search

## Title
Insensitive Subfolder Search Via Findstr.EXE

## ID
04936b66-3915-43ad-a8e5-809eadfd1141

## Author
Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)

## Date
2020-10-05

## Tags
attack.defense-evasion, attack.t1218, attack.t1564.004, attack.t1552.001, attack.t1105

## Description
Detects execution of findstr with the "s" and "i" flags for a "subfolder" and "insensitive" search respectively. Attackers sometimes leverage this built-in utility to search the system for interesting files or filter through results of commands.


## References
https://lolbas-project.github.io/lolbas/Binaries/Findstr/
https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/
https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f

## False Positives
Administrative or software activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "findstr" OR TgtProcImagePath endswithCIS "findstr.exe") AND ((TgtProcCmdLine containsCIS " -i " OR TgtProcCmdLine containsCIS " /i " OR TgtProcCmdLine containsCIS " â€“i " OR TgtProcCmdLine containsCIS " â€”i " OR TgtProcCmdLine containsCIS " â€•i ") AND (TgtProcCmdLine containsCIS " -s " OR TgtProcCmdLine containsCIS " /s " OR TgtProcCmdLine containsCIS " â€“s " OR TgtProcCmdLine containsCIS " â€”s " OR TgtProcCmdLine containsCIS " â€•s "))))

```