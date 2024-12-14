# proc_creation_win_sysinternals_eula_accepted

## Title
Potential Execution of Sysinternals Tools

## ID
7cccd811-7ae9-4ebe-9afd-cb5c406b824b

## Author
Markus Neis

## Date
2017-08-28

## Tags
attack.resource-development, attack.t1588.002

## Description
Detects command lines that contain the 'accepteula' flag which could be a sign of execution of one of the Sysinternals tools

## References
https://twitter.com/Moti_B/status/1008587936735035392

## False Positives
Legitimate use of SysInternals tools
Programs that use the same command line flag

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -accepteula" OR TgtProcCmdLine containsCIS " /accepteula" OR TgtProcCmdLine containsCIS " â€“accepteula" OR TgtProcCmdLine containsCIS " â€”accepteula" OR TgtProcCmdLine containsCIS " â€•accepteula"))

```