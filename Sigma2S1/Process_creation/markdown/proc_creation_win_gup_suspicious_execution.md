# proc_creation_win_gup_suspicious_execution

## Title
Suspicious GUP Usage

## ID
0a4f6091-223b-41f6-8743-f322ec84930b

## Author
Florian Roth (Nextron Systems)

## Date
2019-02-06

## Tags
attack.defense-evasion, attack.t1574.002

## Description
Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks

## References
https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html

## False Positives
Execution of tools named GUP.exe and located in folders different than Notepad++\updater

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\GUP.exe" AND (NOT ((TgtProcImagePath endswithCIS "\Program Files\Notepad++\updater\GUP.exe" OR TgtProcImagePath endswithCIS "\Program Files (x86)\Notepad++\updater\GUP.exe") OR (TgtProcImagePath containsCIS "\Users\" AND (TgtProcImagePath endswithCIS "\AppData\Local\Notepad++\updater\GUP.exe" OR TgtProcImagePath endswithCIS "\AppData\Roaming\Notepad++\updater\GUP.exe"))))))

```