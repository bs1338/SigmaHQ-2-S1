# proc_creation_win_remote_access_tools_screenconnect_webshell

## Title
Remote Access Tool - ScreenConnect Server Web Shell Execution

## ID
b19146a3-25d4-41b4-928b-1e2a92641b1b

## Author
Jason Rathbun (Blackpoint Cyber)

## Date
2024-02-26

## Tags
attack.initial-access, attack.t1190

## Description
Detects potential web shell execution from the ScreenConnect server process.

## References
https://blackpointcyber.com/resources/blog/breaking-through-the-screen/
https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\csc.exe") AND SrcProcImagePath endswithCIS "\ScreenConnect.Service.exe"))

```