# proc_creation_win_rundll32_sys

## Title
Suspicious Rundll32 Activity Invoking Sys File

## ID
731231b9-0b5d-4219-94dd-abb6959aa7ea

## Author
Florian Roth (Nextron Systems)

## Date
2021-03-05

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects suspicious process related to rundll32 based on command line that includes a *.sys file as seen being used by UNC2452

## References
https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "rundll32.exe" AND (TgtProcCmdLine containsCIS ".sys," OR TgtProcCmdLine containsCIS ".sys ")))

```