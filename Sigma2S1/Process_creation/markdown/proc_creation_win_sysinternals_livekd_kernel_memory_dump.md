# proc_creation_win_sysinternals_livekd_kernel_memory_dump

## Title
Kernel Memory Dump Via LiveKD

## ID
c7746f1c-47d3-43d6-8c45-cd1e54b6b0a2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-16

## Tags
attack.defense-evasion

## Description
Detects execution of LiveKD with the "-m" flag to potentially dump the kernel memory

## References
https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
https://4sysops.com/archives/creating-a-complete-memory-dump-without-a-blue-screen/
https://kb.acronis.com/content/60892

## False Positives
Unlikely in production environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -m" OR TgtProcCmdLine containsCIS " /m" OR TgtProcCmdLine containsCIS " â€“m" OR TgtProcCmdLine containsCIS " â€”m" OR TgtProcCmdLine containsCIS " â€•m") AND (TgtProcImagePath endswithCIS "\livekd.exe" OR TgtProcImagePath endswithCIS "\livekd64.exe")))

```