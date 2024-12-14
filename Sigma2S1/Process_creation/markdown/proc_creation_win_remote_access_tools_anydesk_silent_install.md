# proc_creation_win_remote_access_tools_anydesk_silent_install

## Title
Remote Access Tool - AnyDesk Silent Installation

## ID
114e7f1c-f137-48c8-8f54-3088c24ce4b9

## Author
Ján Trenčanský

## Date
2021-08-06

## Tags
attack.command-and-control, attack.t1219

## Description
Detects AnyDesk Remote Desktop silent installation. Which can be used by attackers to gain remote access.

## References
https://twitter.com/TheDFIRReport/status/1423361119926816776?s=20
https://support.anydesk.com/Automatic_Deployment

## False Positives
Legitimate deployment of AnyDesk

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "--install" AND TgtProcCmdLine containsCIS "--start-with-win" AND TgtProcCmdLine containsCIS "--silent"))

```