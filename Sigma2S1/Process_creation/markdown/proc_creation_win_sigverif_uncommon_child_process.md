# proc_creation_win_sigverif_uncommon_child_process

## Title
Uncommon Sigverif.EXE Child Process

## ID
7d4aaec2-08ed-4430-8b96-28420e030e04

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1216

## Description
Detects uncommon child processes spawning from "sigverif.exe", which could indicate potential abuse of the latter as a living of the land binary in order to proxy execution.


## References
https://www.hexacorn.com/blog/2018/04/27/i-shot-the-sigverif-exe-the-gui-based-lolbin/
https://twitter.com/0gtweet/status/1457676633809330184

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\sigverif.exe" AND (NOT (TgtProcImagePath In Contains AnyCase ("C:\Windows\System32\WerFault.exe","C:\Windows\SysWOW64\WerFault.exe")))))

```