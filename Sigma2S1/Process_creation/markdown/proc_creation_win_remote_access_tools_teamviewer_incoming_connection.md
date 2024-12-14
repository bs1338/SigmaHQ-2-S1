# proc_creation_win_remote_access_tools_teamviewer_incoming_connection

## Title
Remote Access Tool - Team Viewer Session Started On Windows Host

## ID
ab70c354-d9ac-4e11-bbb6-ec8e3b153357

## Author
Josh Nickels, Qi Nan

## Date
2024-03-11

## Tags
attack.initial-access, attack.t1133

## Description
Detects the command line executed when TeamViewer starts a session started by a remote host.
Once a connection has been started, an investigator can verify the connection details by viewing the "incoming_connections.txt" log file in the TeamViewer folder.


## References
Internal Research

## False Positives
Legitimate usage of TeamViewer

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine endswithCIS "TeamViewer_Desktop.exe --IPCport 5939 --Module 1" AND TgtProcImagePath = "TeamViewer_Desktop.exe" AND SrcProcImagePath = "TeamViewer_Service.exe"))

```