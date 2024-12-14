# proc_creation_win_powershell_exec_data_file

## Title
Powershell Inline Execution From A File

## ID
ee218c12-627a-4d27-9e30-d6fb2fe22ed2

## Author
frack113

## Date
2022-12-25

## Tags
attack.execution, attack.t1059.001

## Description
Detects inline execution of PowerShell code from a file

## References
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=50

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "iex " OR TgtProcCmdLine containsCIS "Invoke-Expression " OR TgtProcCmdLine containsCIS "Invoke-Command " OR TgtProcCmdLine containsCIS "icm ") AND TgtProcCmdLine containsCIS " -raw" AND (TgtProcCmdLine containsCIS "cat " OR TgtProcCmdLine containsCIS "get-content " OR TgtProcCmdLine containsCIS "type ")))

```