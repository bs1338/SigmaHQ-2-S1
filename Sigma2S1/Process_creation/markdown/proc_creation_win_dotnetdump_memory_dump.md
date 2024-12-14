# proc_creation_win_dotnetdump_memory_dump

## Title
Process Memory Dump Via Dotnet-Dump

## ID
53d8d3e1-ca33-4012-adf3-e05a4d652e34

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-14

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the execution of "dotnet-dump" with the "collect" flag. The execution could indicate potential process dumping of critical processes such as LSASS.


## References
https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-dump#dotnet-dump-collect
https://twitter.com/bohops/status/1635288066909966338

## False Positives
Process dumping is the expected behavior of the tool. So false positives are expected in legitimate usage. The PID/Process Name of the process being dumped needs to be investigated

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "collect" AND TgtProcImagePath endswithCIS "\dotnet-dump.exe"))

```