# proc_creation_win_driverquery_usage

## Title
DriverQuery.EXE Execution

## ID
a20def93-0709-4eae-9bd2-31206e21e6b2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-19

## Tags
attack.discovery

## Description
Detect usage of the "driverquery" utility. Which can be used to perform reconnaissance on installed drivers

## References
https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts/
https://www.vmray.com/cyber-security-blog/analyzing-ursnif-behavior-malware-sandbox/
https://www.fireeye.com/blog/threat-research/2020/01/saigon-mysterious-ursnif-fork.html

## False Positives
Legitimate use by third party tools in order to investigate installed drivers

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "driverquery.exe" AND (NOT ((SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\wscript.exe") OR (SrcProcImagePath containsCIS "\AppData\Local\" OR SrcProcImagePath containsCIS "\Users\Public\" OR SrcProcImagePath containsCIS "\Windows\Temp\")))))

```