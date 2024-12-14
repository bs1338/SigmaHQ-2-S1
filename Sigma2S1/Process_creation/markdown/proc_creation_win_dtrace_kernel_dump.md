# proc_creation_win_dtrace_kernel_dump

## Title
Suspicious Kernel Dump Using Dtrace

## ID
7124aebe-4cd7-4ccb-8df0-6d6b93c96795

## Author
Florian Roth (Nextron Systems)

## Date
2021-12-28

## Tags
attack.discovery, attack.t1082

## Description
Detects suspicious way to dump the kernel on Windows systems using dtrace.exe, which is available on Windows systems since Windows 10 19H1

## References
https://twitter.com/0gtweet/status/1474899714290208777?s=12
https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "syscall:::return" AND TgtProcCmdLine containsCIS "lkd(") OR (TgtProcCmdLine containsCIS "lkd(0)" AND TgtProcImagePath endswithCIS "\dtrace.exe")))

```