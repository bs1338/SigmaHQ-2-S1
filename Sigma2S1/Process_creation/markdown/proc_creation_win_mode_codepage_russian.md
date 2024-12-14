# proc_creation_win_mode_codepage_russian

## Title
CodePage Modification Via MODE.COM To Russian Language

## ID
12fbff88-16b5-4b42-9754-cd001a789fb3

## Author
Joseliyo Sanchez, @Joseliyo_Jstnk

## Date
2024-01-17

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects a CodePage modification using the "mode.com" utility to Russian language.
This behavior has been used by threat actors behind Dharma ransomware.


## References
https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mode
https://strontic.github.io/xcyclopedia/library/mode.com-59D1ED51ACB8C3D50F1306FD75F20E99.html
https://www.virustotal.com/gui/file/5e75ef02517afd6e8ba6462b19217dc4a5a574abb33d10eb0f2bab49d8d48c22/behavior

## False Positives
Russian speaking people changing the CodePage

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " con " AND TgtProcCmdLine containsCIS " cp " AND TgtProcCmdLine containsCIS " select=") AND (TgtProcCmdLine endswithCIS "=1251" OR TgtProcCmdLine endswithCIS "=866")) AND TgtProcImagePath endswithCIS "\mode.com"))

```