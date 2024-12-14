# file_event_win_susp_windows_terminal_profile

## Title
Windows Terminal Profile Settings Modification By Uncommon Process

## ID
9b64de98-9db3-4033-bd7a-f51430105f00

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-07-22

## Tags
attack.persistence, attack.t1547.015

## Description
Detects the creation or modification of the Windows Terminal Profile settings file "settings.json" by an uncommon process.

## References
https://github.com/redcanaryco/atomic-red-team/blob/74438b0237d141ee9c99747976447dc884cb1a39/atomics/T1547.015/T1547.015.md#atomic-test-1---persistence-by-modifying-windows-terminal-profile
https://twitter.com/nas_bench/status/1550836225652686848

## False Positives
Some false positives may occur with admin scripts that set WT settings.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\wscript.exe") AND TgtFilePath endswithCIS "\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"))

```