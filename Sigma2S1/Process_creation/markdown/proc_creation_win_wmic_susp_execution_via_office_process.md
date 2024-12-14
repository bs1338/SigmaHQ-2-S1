# proc_creation_win_wmic_susp_execution_via_office_process

## Title
Suspicious WMIC Execution Via Office Process

## ID
e1693bc8-7168-4eab-8718-cdcaa68a1738

## Author
Vadim Khrykov, Cyb3rEng

## Date
2021-08-23

## Tags
attack.t1204.002, attack.t1047, attack.t1218.010, attack.execution, attack.defense-evasion

## Description
Office application called wmic to proxye execution through a LOLBIN process. This is often used to break suspicious parent-child chain (Office app spawns LOLBin).

## References
https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/02bcbfc2bfb8b4da601bb30de0344ae453aa1afe/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\WINWORD.EXE" OR SrcProcImagePath endswithCIS "\EXCEL.EXE" OR SrcProcImagePath endswithCIS "\POWERPNT.exe" OR SrcProcImagePath endswithCIS "\MSPUB.exe" OR SrcProcImagePath endswithCIS "\VISIO.exe" OR SrcProcImagePath endswithCIS "\MSACCESS.EXE" OR SrcProcImagePath endswithCIS "\EQNEDT32.EXE" OR SrcProcImagePath endswithCIS "\ONENOTE.EXE" OR SrcProcImagePath endswithCIS "\wordpad.exe" OR SrcProcImagePath endswithCIS "\wordview.exe") AND ((TgtProcCmdLine containsCIS "regsvr32" OR TgtProcCmdLine containsCIS "rundll32" OR TgtProcCmdLine containsCIS "msiexec" OR TgtProcCmdLine containsCIS "mshta" OR TgtProcCmdLine containsCIS "verclsid" OR TgtProcCmdLine containsCIS "wscript" OR TgtProcCmdLine containsCIS "cscript") AND (TgtProcCmdLine containsCIS "process" AND TgtProcCmdLine containsCIS "create" AND TgtProcCmdLine containsCIS "call")) AND TgtProcImagePath endswithCIS "\wbem\WMIC.exe"))

```