# proc_creation_win_lolbin_pubprn

## Title
Pubprn.vbs Proxy Execution

## ID
1fb76ab8-fa60-4b01-bddd-71e89bf555da

## Author
frack113

## Date
2022-05-28

## Tags
attack.defense-evasion, attack.t1216.001

## Description
Detects the use of the 'Pubprn.vbs' Microsoft signed script to execute commands.

## References
https://lolbas-project.github.io/lolbas/Scripts/Pubprn/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\pubprn.vbs" AND TgtProcCmdLine containsCIS "script:"))

```