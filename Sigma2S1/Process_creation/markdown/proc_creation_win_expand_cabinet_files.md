# proc_creation_win_expand_cabinet_files

## Title
Potentially Suspicious Cabinet File Expansion

## ID
9f107a84-532c-41af-b005-8d12a607639f

## Author
Bhabesh Raj, X__Junior (Nextron Systems)

## Date
2021-07-30

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the expansion or decompression of cabinet files from potentially suspicious or uncommon locations, e.g. seen in Iranian MeteorExpress related attacks

## References
https://labs.sentinelone.com/meteorexpress-mysterious-wiper-paralyzes-iranian-trains-with-epic-troll
https://blog.malwarebytes.com/threat-intelligence/2021/08/new-variant-of-konni-malware-used-in-campaign-targetting-russia/

## False Positives
System administrator Usage

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "-F:" OR TgtProcCmdLine containsCIS "/F:" OR TgtProcCmdLine containsCIS "â€“F:" OR TgtProcCmdLine containsCIS "â€”F:" OR TgtProcCmdLine containsCIS "â€•F:") AND TgtProcImagePath endswithCIS "\expand.exe") AND ((TgtProcCmdLine containsCIS ":\Perflogs\" OR TgtProcCmdLine containsCIS ":\ProgramData" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\Admin$\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Roaming\" OR TgtProcCmdLine containsCIS "\C$\" OR TgtProcCmdLine containsCIS "\Temporary Internet") OR ((TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Favorites\") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Favourites\") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Contacts\"))) AND (NOT (TgtProcCmdLine containsCIS "C:\ProgramData\Dell\UpdateService\Temp\" AND SrcProcImagePath = "C:\Program Files (x86)\Dell\UpdateService\ServiceShell.exe"))))

```