# proc_creation_win_susp_embed_exe_lnk

## Title
Hidden Powershell in Link File Pattern

## ID
30e92f50-bb5a-4884-98b5-d20aa80f3d7a

## Author
frack113

## Date
2022-02-06

## Tags
attack.execution, attack.t1059.001

## Description
Detects events that appear when a user click on a link file with a powershell command in it

## References
https://www.x86matthew.com/view_post?id=embed_exe_lnk

## False Positives
Legitimate commands in .lnk files

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "powershell" AND TgtProcCmdLine containsCIS ".lnk") AND TgtProcImagePath = "C:\Windows\System32\cmd.exe" AND SrcProcImagePath = "C:\Windows\explorer.exe"))

```