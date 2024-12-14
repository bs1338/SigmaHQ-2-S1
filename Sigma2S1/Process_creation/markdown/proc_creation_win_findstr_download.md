# proc_creation_win_findstr_download

## Title
Remote File Download Via Findstr.EXE

## ID
587254ee-a24b-4335-b3cd-065c0f1f4baa

## Author
Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)

## Date
2020-10-05

## Tags
attack.defense-evasion, attack.t1218, attack.t1564.004, attack.t1552.001, attack.t1105

## Description
Detects execution of "findstr" with specific flags and a remote share path. This specific set of CLI flags would allow "findstr" to download the content of the file located on the remote share as described in the LOLBAS entry.


## References
https://lolbas-project.github.io/lolbas/Binaries/Findstr/
https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/
https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "findstr" OR TgtProcImagePath endswithCIS "findstr.exe") AND ((TgtProcCmdLine containsCIS " -v " OR TgtProcCmdLine containsCIS " /v " OR TgtProcCmdLine containsCIS " â€“v " OR TgtProcCmdLine containsCIS " â€”v " OR TgtProcCmdLine containsCIS " â€•v ") AND (TgtProcCmdLine containsCIS " -l " OR TgtProcCmdLine containsCIS " /l " OR TgtProcCmdLine containsCIS " â€“l " OR TgtProcCmdLine containsCIS " â€”l " OR TgtProcCmdLine containsCIS " â€•l ") AND TgtProcCmdLine containsCIS "\\")))

```