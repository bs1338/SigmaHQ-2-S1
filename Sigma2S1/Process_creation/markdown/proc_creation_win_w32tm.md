# proc_creation_win_w32tm

## Title
Use of W32tm as Timer

## ID
6da2c9f5-7c53-401b-aacb-92c040ce1215

## Author
frack113

## Date
2022-09-25

## Tags
attack.discovery, attack.t1124

## Description
When configured with suitable command line arguments, w32tm can act as a delay mechanism

## References
https://github.com/redcanaryco/atomic-red-team/blob/d0dad62dbcae9c60c519368e82c196a3db577055/atomics/T1124/T1124.md
https://blogs.blackberry.com/en/2022/05/dirty-deeds-done-dirt-cheap-russian-rat-offers-backdoor-bargains

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/stripchart" AND TgtProcCmdLine containsCIS "/computer:" AND TgtProcCmdLine containsCIS "/period:" AND TgtProcCmdLine containsCIS "/dataonly" AND TgtProcCmdLine containsCIS "/samples:") AND TgtProcImagePath endswithCIS "\w32tm.exe"))

```