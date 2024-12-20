# proc_creation_win_shutdown_logoff

## Title
Suspicious Execution of Shutdown to Log Out

## ID
ec290c06-9b6b-4338-8b6b-095c0f284f10

## Author
frack113

## Date
2022-10-01

## Tags
attack.impact, attack.t1529

## Description
Detects the rare use of the command line tool shutdown to logoff a user

## References
https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1529/T1529.md
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/l" AND TgtProcImagePath endswithCIS "\shutdown.exe"))

```