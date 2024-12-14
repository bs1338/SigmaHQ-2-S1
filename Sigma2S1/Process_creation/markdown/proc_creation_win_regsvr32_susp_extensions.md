# proc_creation_win_regsvr32_susp_extensions

## Title
Regsvr32 DLL Execution With Suspicious File Extension

## ID
089fc3d2-71e8-4763-a8a5-c97fbb0a403e

## Author
Florian Roth (Nextron Systems), frack113

## Date
2021-11-29

## Tags
attack.defense-evasion, attack.t1218.010

## Description
Detects the execution of REGSVR32.exe with DLL files masquerading as other files

## References
https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/
https://blog.talosintelligence.com/2021/10/threat-hunting-in-large-datasets-by.html
https://guides.lib.umich.edu/c.php?g=282942&p=1885348

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS ".bin" OR TgtProcCmdLine endswithCIS ".bmp" OR TgtProcCmdLine endswithCIS ".cr2" OR TgtProcCmdLine endswithCIS ".dat" OR TgtProcCmdLine endswithCIS ".eps" OR TgtProcCmdLine endswithCIS ".gif" OR TgtProcCmdLine endswithCIS ".ico" OR TgtProcCmdLine endswithCIS ".jpeg" OR TgtProcCmdLine endswithCIS ".jpg" OR TgtProcCmdLine endswithCIS ".nef" OR TgtProcCmdLine endswithCIS ".orf" OR TgtProcCmdLine endswithCIS ".png" OR TgtProcCmdLine endswithCIS ".raw" OR TgtProcCmdLine endswithCIS ".sr2" OR TgtProcCmdLine endswithCIS ".temp" OR TgtProcCmdLine endswithCIS ".tif" OR TgtProcCmdLine endswithCIS ".tiff" OR TgtProcCmdLine endswithCIS ".tmp" OR TgtProcCmdLine endswithCIS ".rtf" OR TgtProcCmdLine endswithCIS ".txt") AND TgtProcImagePath endswithCIS "\regsvr32.exe"))

```