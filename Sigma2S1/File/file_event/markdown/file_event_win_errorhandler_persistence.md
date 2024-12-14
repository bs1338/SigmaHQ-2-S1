# file_event_win_errorhandler_persistence

## Title
Potential Persistence Attempt Via ErrorHandler.Cmd

## ID
15904280-565c-4b73-9303-3291f964e7f9

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-09

## Tags
attack.persistence

## Description
Detects creation of a file named "ErrorHandler.cmd" in the "C:\WINDOWS\Setup\Scripts\" directory which could be used as a method of persistence
 The content of C:\WINDOWS\Setup\Scripts\ErrorHandler.cmd is read whenever some tools under C:\WINDOWS\System32\oobe\ (e.g. Setup.exe) fail to run for any reason.


## References
https://www.hexacorn.com/blog/2022/01/16/beyond-good-ol-run-key-part-135/
https://github.com/last-byte/PersistenceSniper

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "\WINDOWS\Setup\Scripts\ErrorHandler.cmd")

```