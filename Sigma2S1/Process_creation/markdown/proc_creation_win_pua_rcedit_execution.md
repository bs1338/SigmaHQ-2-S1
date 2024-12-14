# proc_creation_win_pua_rcedit_execution

## Title
PUA - Potential PE Metadata Tamper Using Rcedit

## ID
0c92f2e6-f08f-4b73-9216-ecb0ca634689

## Author
Micah Babinski

## Date
2022-12-11

## Tags
attack.defense-evasion, attack.t1036.003, attack.t1036, attack.t1027.005, attack.t1027

## Description
Detects the use of rcedit to potentially alter executable PE metadata properties, which could conceal efforts to rename system utilities for defense evasion.

## References
https://security.stackexchange.com/questions/210843/is-it-possible-to-change-original-filename-of-an-exe
https://www.virustotal.com/gui/file/02e8e8c5d430d8b768980f517b62d7792d690982b9ba0f7e04163cbc1a6e7915
https://github.com/electron/rcedit

## False Positives
Legitimate use of the tool by administrators or users to update metadata of a binary

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "OriginalFileName" OR TgtProcCmdLine containsCIS "CompanyName" OR TgtProcCmdLine containsCIS "FileDescription" OR TgtProcCmdLine containsCIS "ProductName" OR TgtProcCmdLine containsCIS "ProductVersion" OR TgtProcCmdLine containsCIS "LegalCopyright") AND TgtProcCmdLine containsCIS "--set-" AND ((TgtProcImagePath endswithCIS "\rcedit-x64.exe" OR TgtProcImagePath endswithCIS "\rcedit-x86.exe") OR TgtProcDisplayName = "Edit resources of exe" OR TgtProcDisplayName = "rcedit")))

```