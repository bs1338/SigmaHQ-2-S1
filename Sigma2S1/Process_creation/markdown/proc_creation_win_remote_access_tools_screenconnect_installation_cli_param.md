# proc_creation_win_remote_access_tools_screenconnect_installation_cli_param

## Title
Remote Access Tool - ScreenConnect Installation Execution

## ID
75bfe6e6-cd8e-429e-91d3-03921e1d7962

## Author
Florian Roth (Nextron Systems)

## Date
2021-02-11

## Tags
attack.initial-access, attack.t1133

## Description
Detects ScreenConnect program starts that establish a remote access to a system.

## References
https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies

## False Positives
Legitimate use by administrative staff

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "e=Access&" AND TgtProcCmdLine containsCIS "y=Guest&" AND TgtProcCmdLine containsCIS "&p=" AND TgtProcCmdLine containsCIS "&c=" AND TgtProcCmdLine containsCIS "&k="))

```