# proc_creation_win_powershell_base64_encoded_cmd

## Title
Suspicious Encoded PowerShell Command Line

## ID
ca2092a1-c273-4878-9b4b-0d60115bf5ea

## Author
Florian Roth (Nextron Systems), Markus Neis, Jonhnathan Ribeiro, Daniil Yugoslavskiy, Anton Kutepov, oscd.community

## Date
2018-09-03

## Tags
attack.execution, attack.t1059.001

## Description
Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)

## References
https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e

## False Positives


## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (((TgtProcCmdLine containsCIS " JAB" OR TgtProcCmdLine containsCIS " SUVYI" OR TgtProcCmdLine containsCIS " SQBFAFgA" OR TgtProcCmdLine containsCIS " aQBlAHgA" OR TgtProcCmdLine containsCIS " aWV4I" OR TgtProcCmdLine containsCIS " IAA" OR TgtProcCmdLine containsCIS " IAB" OR TgtProcCmdLine containsCIS " UwB" OR TgtProcCmdLine containsCIS " cwB") AND TgtProcCmdLine containsCIS " -e") OR (TgtProcCmdLine containsCIS ".exe -ENCOD " OR TgtProcCmdLine containsCIS " BA^J e-")) AND (NOT TgtProcCmdLine containsCIS " -ExecutionPolicy remotesigned ")))

```