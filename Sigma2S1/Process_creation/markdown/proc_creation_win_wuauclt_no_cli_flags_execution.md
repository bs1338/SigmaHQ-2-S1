# proc_creation_win_wuauclt_no_cli_flags_execution

## Title
Suspicious Windows Update Agent Empty Cmdline

## ID
52d097e2-063e-4c9c-8fbb-855c8948d135

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-26

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects suspicious Windows Update Agent activity in which a wuauclt.exe process command line doesn't contain any command line flags


## References
https://redcanary.com/blog/blackbyte-ransomware/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS "Wuauclt" OR TgtProcCmdLine endswithCIS "Wuauclt.exe") AND TgtProcImagePath endswithCIS "\Wuauclt.exe"))

```