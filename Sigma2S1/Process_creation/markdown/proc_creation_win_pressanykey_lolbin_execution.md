# proc_creation_win_pressanykey_lolbin_execution

## Title
Visual Studio NodejsTools PressAnyKey Arbitrary Binary Execution

## ID
a20391f8-76fb-437b-abc0-dba2df1952c6

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-01-11

## Tags
attack.execution, attack.defense-evasion, attack.t1218

## Description
Detects child processes of Microsoft.NodejsTools.PressAnyKey.exe that can be used to execute any other binary

## References
https://twitter.com/mrd0x/status/1463526834918854661
https://gist.github.com/nasbench/a989ce64cefa8081bd50cf6ad8c491b5

## False Positives
Legitimate use by developers as part of NodeJS development with Visual Studio Tools

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND SrcProcImagePath endswithCIS "\Microsoft.NodejsTools.PressAnyKey.exe")

```