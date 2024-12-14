# file_event_win_sysinternals_procexp_driver_susp_creation

## Title
Process Explorer Driver Creation By Non-Sysinternals Binary

## ID
de46c52b-0bf8-4936-a327-aace94f94ac6

## Author
Florian Roth (Nextron Systems)

## Date
2023-05-05

## Tags
attack.persistence, attack.privilege-escalation, attack.t1068

## Description
Detects creation of the Process Explorer drivers by processes other than Process Explorer (procexp) itself.
Hack tools or malware may use the Process Explorer driver to elevate privileges, drops it to disk for a few moments, runs a service using that driver and removes it afterwards.


## References
https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
https://github.com/Yaxser/Backstab
https://www.elastic.co/security-labs/stopping-vulnerable-driver-attacks
https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/

## False Positives
Some false positives may occur with legitimate renamed process explorer binaries

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\PROCEXP" AND TgtFilePath endswithCIS ".sys") AND (NOT (SrcProcImagePath endswithCIS "\procexp.exe" OR SrcProcImagePath endswithCIS "\procexp64.exe"))))

```