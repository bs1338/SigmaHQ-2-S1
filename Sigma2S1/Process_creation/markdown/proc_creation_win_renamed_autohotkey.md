# proc_creation_win_renamed_autohotkey

## Title
Renamed AutoHotkey.EXE Execution

## ID
0f16d9cf-0616-45c8-8fad-becc11b5a41c

## Author
Nasreddine Bencherchali

## Date
2023-02-07

## Tags
attack.defense-evasion

## Description
Detects execution of a renamed autohotkey.exe binary based on PE metadata fields

## References
https://www.autohotkey.com/download/
https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcDisplayName containsCIS "AutoHotkey" OR TgtProcDisplayName containsCIS "AutoHotkey") AND (NOT ((TgtProcImagePath endswithCIS "\AutoHotkey.exe" OR TgtProcImagePath endswithCIS "\AutoHotkey32.exe" OR TgtProcImagePath endswithCIS "\AutoHotkey32_UIA.exe" OR TgtProcImagePath endswithCIS "\AutoHotkey64.exe" OR TgtProcImagePath endswithCIS "\AutoHotkey64_UIA.exe" OR TgtProcImagePath endswithCIS "\AutoHotkeyA32.exe" OR TgtProcImagePath endswithCIS "\AutoHotkeyA32_UIA.exe" OR TgtProcImagePath endswithCIS "\AutoHotkeyU32.exe" OR TgtProcImagePath endswithCIS "\AutoHotkeyU32_UIA.exe" OR TgtProcImagePath endswithCIS "\AutoHotkeyU64.exe" OR TgtProcImagePath endswithCIS "\AutoHotkeyU64_UIA.exe") OR TgtProcImagePath containsCIS "\AutoHotkey"))))

```