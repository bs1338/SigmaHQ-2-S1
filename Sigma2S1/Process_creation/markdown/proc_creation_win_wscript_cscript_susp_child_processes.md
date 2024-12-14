# proc_creation_win_wscript_cscript_susp_child_processes

## Title
Cscript/Wscript Potentially Suspicious Child Process

## ID
b6676963-0353-4f88-90f5-36c20d443c6a

## Author
Nasreddine Bencherchali (Nextron Systems), Alejandro Houspanossian ('@lekz86')

## Date
2023-05-15

## Tags
attack.execution

## Description
Detects potentially suspicious child processes of Wscript/Cscript. These include processes such as rundll32 with uncommon exports or PowerShell spawning rundll32 or regsvr32.
Malware such as Pikabot and Qakbot were seen using similar techniques as well as many others.


## References
Internal Research
https://github.com/pr0xylife/Pikabot/blob/main/Pikabot_30.10.2023.txt
https://github.com/pr0xylife/Pikabot/blob/main/Pikabot_22.12.2023.txt

## False Positives
Some false positives might occur with admin or third party software scripts. Investigate and apply additional filters accordingly.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\wscript.exe" OR SrcProcImagePath endswithCIS "\cscript.exe") AND (TgtProcImagePath endswithCIS "\rundll32.exe" OR ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND ((TgtProcCmdLine containsCIS "mshta" AND TgtProcCmdLine containsCIS "http") OR (TgtProcCmdLine containsCIS "rundll32" OR TgtProcCmdLine containsCIS "regsvr32" OR TgtProcCmdLine containsCIS "msiexec")))) AND (NOT ((TgtProcCmdLine containsCIS "UpdatePerUserSystemParameters" OR TgtProcCmdLine containsCIS "PrintUIEntry" OR TgtProcCmdLine containsCIS "ClearMyTracksByProcess") AND TgtProcImagePath endswithCIS "\rundll32.exe"))))

```