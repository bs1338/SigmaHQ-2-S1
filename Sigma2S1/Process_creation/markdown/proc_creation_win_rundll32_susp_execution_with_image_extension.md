# proc_creation_win_rundll32_susp_execution_with_image_extension

## Title
Suspicious Rundll32 Execution With Image Extension

## ID
4aa6040b-3f28-44e3-a769-9208e5feb5ec

## Author
Hieu Tran

## Date
2023-03-13

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects the execution of Rundll32.exe with DLL files masquerading as image files

## References
https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".bmp" OR TgtProcCmdLine containsCIS ".cr2" OR TgtProcCmdLine containsCIS ".eps" OR TgtProcCmdLine containsCIS ".gif" OR TgtProcCmdLine containsCIS ".ico" OR TgtProcCmdLine containsCIS ".jpeg" OR TgtProcCmdLine containsCIS ".jpg" OR TgtProcCmdLine containsCIS ".nef" OR TgtProcCmdLine containsCIS ".orf" OR TgtProcCmdLine containsCIS ".png" OR TgtProcCmdLine containsCIS ".raw" OR TgtProcCmdLine containsCIS ".sr2" OR TgtProcCmdLine containsCIS ".tif" OR TgtProcCmdLine containsCIS ".tiff") AND TgtProcImagePath endswithCIS "\rundll32.exe"))

```