# proc_creation_win_attrib_hiding_files

## Title
Hiding Files with Attrib.exe

## ID
4281cb20-2994-4580-aa63-c8b86d019934

## Author
Sami Ruohonen

## Date
2019-01-16

## Tags
attack.defense-evasion, attack.t1564.001

## Description
Detects usage of attrib.exe to hide files from users.

## References
https://unit42.paloaltonetworks.com/unit42-sure-ill-take-new-combojack-malware-alters-clipboards-steal-cryptocurrency/
https://www.uptycs.com/blog/lolbins-are-no-laughing-matter

## False Positives
IgfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)
Msiexec.exe hiding desktop.ini

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " +h " AND TgtProcImagePath endswithCIS "\attrib.exe") AND (NOT TgtProcCmdLine containsCIS "\desktop.ini ") AND (NOT (TgtProcCmdLine = "+R +H +S +A \\*.cui" AND SrcProcCmdLine = "C:\WINDOWS\system32\\*.bat" AND SrcProcImagePath endswithCIS "\cmd.exe"))))

```