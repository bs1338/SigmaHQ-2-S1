# proc_creation_win_susp_priv_escalation_via_named_pipe

## Title
Privilege Escalation via Named Pipe Impersonation

## ID
9bd04a79-dabe-4f1f-a5ff-92430265c96b

## Author
Tim Rauch, Elastic (idea)

## Date
2022-09-27

## Tags
attack.lateral-movement, attack.t1021

## Description
Detects a remote file copy attempt to a hidden network share. This may indicate lateral movement or data staging activity.

## References
https://www.elastic.co/guide/en/security/current/privilege-escalation-via-named-pipe-impersonation.html

## False Positives
Other programs that cause these patterns (please report)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "echo" AND TgtProcCmdLine containsCIS ">" AND TgtProcCmdLine containsCIS "\\.\pipe\") AND (TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\powershell.exe")))

```