# proc_creation_win_winrar_uncommon_folder_execution

## Title
Winrar Execution in Non-Standard Folder

## ID
4ede543c-e098-43d9-a28f-dd784a13132f

## Author
Florian Roth (Nextron Systems), Tigzy

## Date
2021-11-17

## Tags
attack.collection, attack.t1560.001

## Description
Detects a suspicious winrar execution in a folder which is not the default installation folder

## References
https://twitter.com/cyb3rops/status/1460978167628406785

## False Positives
Legitimate use of WinRAR in a folder of a software that bundles WinRAR

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\rar.exe" OR TgtProcImagePath endswithCIS "\winrar.exe") OR TgtProcDisplayName = "Command line RAR") AND (NOT ((TgtProcImagePath containsCIS ":\Program Files (x86)\WinRAR\" OR TgtProcImagePath containsCIS ":\Program Files\WinRAR\") OR TgtProcImagePath endswithCIS "\UnRAR.exe")) AND (NOT TgtProcImagePath containsCIS ":\Windows\Temp\")))

```