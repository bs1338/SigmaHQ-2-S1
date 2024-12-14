# proc_creation_win_registry_typed_paths_persistence

## Title
Persistence Via TypedPaths - CommandLine

## ID
ec88289a-7e1a-4cc3-8d18-bd1f60e4b9ba

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-22

## Tags
attack.persistence

## Description
Detects modification addition to the 'TypedPaths' key in the user or admin registry via the commandline. Which might indicate persistence attempt

## References
https://twitter.com/dez_/status/1560101453150257154
https://forensafe.com/blogs/typedpaths.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths")

```