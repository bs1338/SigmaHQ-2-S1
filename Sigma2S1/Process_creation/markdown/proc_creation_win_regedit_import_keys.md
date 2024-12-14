# proc_creation_win_regedit_import_keys

## Title
Imports Registry Key From a File

## ID
73bba97f-a82d-42ce-b315-9182e76c57b1

## Author
Oddvar Moe, Sander Wiebing, oscd.community

## Date
2020-10-07

## Tags
attack.t1112, attack.defense-evasion

## Description
Detects the import of the specified file to the registry with regedit.exe.

## References
https://lolbas-project.github.io/lolbas/Binaries/Regedit/
https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f

## False Positives
Legitimate import of keys
Evernote

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " /i " OR TgtProcCmdLine containsCIS " /s " OR TgtProcCmdLine containsCIS ".reg") AND TgtProcImagePath endswithCIS "\regedit.exe") AND (NOT ((TgtProcCmdLine containsCIS " -e " OR TgtProcCmdLine containsCIS " /e " OR TgtProcCmdLine containsCIS " â€“e " OR TgtProcCmdLine containsCIS " â€”e " OR TgtProcCmdLine containsCIS " â€•e " OR TgtProcCmdLine containsCIS " -a " OR TgtProcCmdLine containsCIS " /a " OR TgtProcCmdLine containsCIS " â€“a " OR TgtProcCmdLine containsCIS " â€”a " OR TgtProcCmdLine containsCIS " â€•a " OR TgtProcCmdLine containsCIS " -c " OR TgtProcCmdLine containsCIS " /c " OR TgtProcCmdLine containsCIS " â€“c " OR TgtProcCmdLine containsCIS " â€”c " OR TgtProcCmdLine containsCIS " â€•c ") AND TgtProcCmdLine RegExp ":[^ \\\\]"))))

```