# proc_creation_win_cmd_net_use_and_exec_combo

## Title
Suspicious File Execution From Internet Hosted WebDav Share

## ID
f0507c0f-a3a2-40f5-acc6-7f543c334993

## Author
pH-T (Nextron Systems)

## Date
2022-09-01

## Tags
attack.execution, attack.t1059.001

## Description
Detects the execution of the "net use" command to mount a WebDAV server and then immediately execute some content in it. As seen being used in malicious LNK files

## References
https://twitter.com/ShadowChasing1/status/1552595370961944576
https://www.virustotal.com/gui/file/a63376ee1dba76361df73338928e528ca5b20171ea74c24581605366dcaa0104/behavior

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " net use http" AND TgtProcCmdLine containsCIS "& start /b " AND TgtProcCmdLine containsCIS "\DavWWWRoot\") AND (TgtProcCmdLine containsCIS ".exe " OR TgtProcCmdLine containsCIS ".dll " OR TgtProcCmdLine containsCIS ".bat " OR TgtProcCmdLine containsCIS ".vbs " OR TgtProcCmdLine containsCIS ".ps1 ") AND TgtProcImagePath containsCIS "\cmd.exe"))

```