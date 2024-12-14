# proc_creation_win_netsh_fw_delete_rule

## Title
Firewall Rule Deleted Via Netsh.EXE

## ID
1a5fefe6-734f-452e-a07d-fc1c35bce4b2

## Author
frack113

## Date
2022-08-14

## Tags
attack.defense-evasion, attack.t1562.004

## Description
Detects the removal of a port or application rule in the Windows Firewall configuration using netsh

## References
https://app.any.run/tasks/8bbd5b4c-b82d-4e6d-a3ea-d454594a37cc/

## False Positives
Legitimate administration activity
Software installations and removal

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "firewall" AND TgtProcCmdLine containsCIS "delete ") AND TgtProcImagePath endswithCIS "\netsh.exe") AND (NOT (TgtProcCmdLine containsCIS "name=Dropbox" AND SrcProcImagePath endswithCIS "\Dropbox.exe"))))

```