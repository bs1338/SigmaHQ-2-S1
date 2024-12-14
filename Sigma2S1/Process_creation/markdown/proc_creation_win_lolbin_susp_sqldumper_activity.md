# proc_creation_win_lolbin_susp_sqldumper_activity

## Title
Dumping Process via Sqldumper.exe

## ID
23ceaf5c-b6f1-4a32-8559-f2ff734be516

## Author
Kirill Kiryanov, oscd.community

## Date
2020-10-08

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects process dump via legitimate sqldumper.exe binary

## References
https://twitter.com/countuponsec/status/910977826853068800
https://twitter.com/countuponsec/status/910969424215232518
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqldumper/

## False Positives
Legitimate MSSQL Server actions

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "0x0110" OR TgtProcCmdLine containsCIS "0x01100:40") AND TgtProcImagePath endswithCIS "\sqldumper.exe"))

```