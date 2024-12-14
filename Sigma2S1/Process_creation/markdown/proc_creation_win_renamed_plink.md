# proc_creation_win_renamed_plink

## Title
Renamed Plink Execution

## ID
1c12727d-02bf-45ff-a9f3-d49806a3cf43

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-06

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects the execution of a renamed version of the Plink binary

## References
https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/
https://the.earth.li/~sgtatham/putty/0.58/htmldoc/Chapter7.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -l forward" AND TgtProcCmdLine containsCIS " -P " AND TgtProcCmdLine containsCIS " -R ") AND (NOT TgtProcImagePath endswithCIS "\plink.exe")))

```