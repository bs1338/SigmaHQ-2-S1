# proc_creation_win_remote_access_tools_anydesk_piped_password_via_cli

## Title
Remote Access Tool - AnyDesk Piped Password Via CLI

## ID
b1377339-fda6-477a-b455-ac0923f9ec2c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-28

## Tags
attack.command-and-control, attack.t1219

## Description
Detects piping the password to an anydesk instance via CMD and the '--set-password' flag.

## References
https://redcanary.com/blog/misbehaving-rats/

## False Positives
Legitimate piping of the password to anydesk
Some FP could occur with similar tools that uses the same command line '--set-password'

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/c " AND TgtProcCmdLine containsCIS "echo " AND TgtProcCmdLine containsCIS ".exe --set-password"))

```