# proc_creation_win_remote_access_tools_simple_help

## Title
Remote Access Tool - Simple Help Execution

## ID
95e60a2b-4705-444b-b7da-ba0ea81a3ee2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-02-23

## Tags
attack.command-and-control, attack.t1219

## Description
An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)


## References
https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## False Positives
Legitimate usage of the tool

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath containsCIS "\JWrapper-Remote Access\" OR TgtProcImagePath containsCIS "\JWrapper-Remote Support\") AND TgtProcImagePath endswithCIS "\SimpleService.exe"))

```