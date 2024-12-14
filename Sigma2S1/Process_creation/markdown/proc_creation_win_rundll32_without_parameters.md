# proc_creation_win_rundll32_without_parameters

## Title
Rundll32 Execution Without Parameters

## ID
5bb68627-3198-40ca-b458-49f973db8752

## Author
Bartlomiej Czyz, Relativity

## Date
2021-01-31

## Tags
attack.lateral-movement, attack.t1021.002, attack.t1570, attack.execution, attack.t1569.002

## Description
Detects rundll32 execution without parameters as observed when running Metasploit windows/smb/psexec exploit module

## References
https://bczyz1.github.io/2021/01/30/psexec.html

## False Positives
False positives may occur if a user called rundll32 from CLI with no options

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine In Contains AnyCase ("rundll32.exe","rundll32")))

```