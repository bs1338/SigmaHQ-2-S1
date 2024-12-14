# proc_creation_win_lolbin_printbrm

## Title
PrintBrm ZIP Creation of Extraction

## ID
cafeeba3-01da-4ab4-b6c4-a31b1d9730c7

## Author
frack113

## Date
2022-05-02

## Tags
attack.command-and-control, attack.t1105, attack.defense-evasion, attack.t1564.004

## Description
Detects the execution of the LOLBIN PrintBrm.exe, which can be used to create or extract ZIP files. PrintBrm.exe should not be run on a normal workstation.

## References
https://lolbas-project.github.io/lolbas/Binaries/PrintBrm/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -f" AND TgtProcCmdLine containsCIS ".zip") AND TgtProcImagePath endswithCIS "\PrintBrm.exe"))

```