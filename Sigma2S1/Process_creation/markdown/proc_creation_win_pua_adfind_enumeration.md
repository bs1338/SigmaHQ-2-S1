# proc_creation_win_pua_adfind_enumeration

## Title
PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE

## ID
455b9d50-15a1-4b99-853f-8d37655a4c1b

## Author
frack113

## Date
2021-12-13

## Tags
attack.discovery, attack.t1087.002

## Description
Detects active directory enumeration activity using known AdFind CLI flags

## References
https://www.joeware.net/freetools/tools/adfind/
https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1087.002/T1087.002.md

## False Positives
Authorized administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "-sc admincountdmp" OR TgtProcCmdLine containsCIS "-sc exchaddresses" OR (TgtProcCmdLine containsCIS "lockoutduration" OR TgtProcCmdLine containsCIS "lockoutthreshold" OR TgtProcCmdLine containsCIS "lockoutobservationwindow" OR TgtProcCmdLine containsCIS "maxpwdage" OR TgtProcCmdLine containsCIS "minpwdage" OR TgtProcCmdLine containsCIS "minpwdlength" OR TgtProcCmdLine containsCIS "pwdhistorylength" OR TgtProcCmdLine containsCIS "pwdproperties")))

```