# proc_creation_win_dllhost_no_cli_execution

## Title
Dllhost.EXE Execution Anomaly

## ID
e7888eb1-13b0-4616-bd99-4bc0c2b054b9

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-27

## Tags
attack.defense-evasion, attack.t1055

## Description
Detects a "dllhost" process spawning with no commandline arguments which is very rare to happen and could indicate process injection activity or malware mimicking similar system processes.

## References
https://redcanary.com/blog/child-processes/
https://nasbench.medium.com/what-is-the-dllhost-exe-process-actually-running-ef9fe4c19c08
https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/goofy-guineapig/NCSC-MAR-Goofy-Guineapig.pdf

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine In Contains AnyCase ("dllhost.exe","dllhost")) AND TgtProcImagePath endswithCIS "\dllhost.exe") AND (NOT TgtProcCmdLine IS NOT EMPTY)))

```