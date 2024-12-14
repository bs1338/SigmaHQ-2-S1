# proc_creation_win_remote_access_tools_anydesk_susp_exec

## Title
Remote Access Tool - Anydesk Execution From Suspicious Folder

## ID
065b00ca-5d5c-4557-ac95-64a6d0b64d86

## Author
Florian Roth (Nextron Systems)

## Date
2022-05-20

## Tags
attack.command-and-control, attack.t1219

## Description
An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-2---anydesk-files-detected-test-on-windows

## False Positives
Legitimate use of AnyDesk from a non-standard folder

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\AnyDesk.exe" OR TgtProcDisplayName = "AnyDesk" OR TgtProcDisplayName = "AnyDesk" OR TgtProcPublisher = "AnyDesk Software GmbH") AND (NOT (TgtProcImagePath containsCIS "\AppData\" OR TgtProcImagePath containsCIS "Program Files (x86)\AnyDesk" OR TgtProcImagePath containsCIS "Program Files\AnyDesk"))))

```