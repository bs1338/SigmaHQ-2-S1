# proc_creation_win_remote_access_tools_screenconnect

## Title
Remote Access Tool - ScreenConnect Execution

## ID
57bff678-25d1-4d6c-8211-8ca106d12053

## Author
frack113

## Date
2022-02-13

## Tags
attack.command-and-control, attack.t1219

## Description
An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-5---screenconnect-application-download-and-install-on-windows

## False Positives
Legitimate usage of the tool

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcDisplayName = "ScreenConnect Service" OR TgtProcDisplayName = "ScreenConnect" OR TgtProcPublisher = "ScreenConnect Software"))

```