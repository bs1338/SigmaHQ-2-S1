# proc_creation_win_hktl_jlaive_batch_execution

## Title
HackTool - Jlaive In-Memory Assembly Execution

## ID
0a99eb3e-1617-41bd-b095-13dc767f3def

## Author
Jose Luis Sanchez Martinez (@Joseliyo_Jstnk)

## Date
2022-05-24

## Tags
attack.execution, attack.t1059.003

## Description
Detects the use of Jlaive to execute assemblies in a copied PowerShell

## References
https://jstnk9.github.io/jstnk9/research/Jlaive-Antivirus-Evasion-Tool
https://web.archive.org/web/20220514073704/https://github.com/ch2sh/Jlaive

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcCmdLine endswithCIS ".bat" AND SrcProcImagePath endswithCIS "\cmd.exe") AND (((TgtProcCmdLine containsCIS "powershell.exe" AND TgtProcCmdLine containsCIS ".bat.exe") AND TgtProcImagePath endswithCIS "\xcopy.exe") OR ((TgtProcCmdLine containsCIS "pwsh.exe" AND TgtProcCmdLine containsCIS ".bat.exe") AND TgtProcImagePath endswithCIS "\xcopy.exe") OR ((TgtProcCmdLine containsCIS "+s" AND TgtProcCmdLine containsCIS "+h" AND TgtProcCmdLine containsCIS ".bat.exe") AND TgtProcImagePath endswithCIS "\attrib.exe"))))

```