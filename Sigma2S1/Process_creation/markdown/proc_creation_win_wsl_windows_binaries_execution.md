# proc_creation_win_wsl_windows_binaries_execution

## Title
Windows Binary Executed From WSL

## ID
ed825c86-c009-4014-b413-b76003e33d35

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-14

## Tags
attack.execution, attack.defense-evasion, attack.t1202

## Description
Detects the execution of Windows binaries from within a WSL instance.
 This could be used to masquerade parent-child relationships


## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath containsCIS "\\wsl.localhost" AND TgtProcImagePath RegExp "[a-zA-Z]:\\\\"))

```