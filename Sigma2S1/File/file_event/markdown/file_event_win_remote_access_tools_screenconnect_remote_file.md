# file_event_win_remote_access_tools_screenconnect_remote_file

## Title
Remote Access Tool - ScreenConnect Temporary File

## ID
0afecb6e-6223-4a82-99fb-bf5b981e92a5

## Author
Ali Alwashali

## Date
2023-10-10

## Tags
attack.execution, attack.t1059.003

## Description
Detects the creation of files in a specific location by ScreenConnect RMM.
ScreenConnect has feature to remotely execute binaries on a target machine. These binaries will be dropped to ":\Users\<username>\Documents\ConnectWiseControl\Temp\" before execution.


## References
https://github.com/SigmaHQ/sigma/pull/4467

## False Positives
Legitimate use of ScreenConnect

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\ScreenConnect.WindowsClient.exe" AND TgtFilePath containsCIS "\Documents\ConnectWiseControl\Temp\"))

```