# proc_creation_win_driverquery_recon

## Title
Potential Recon Activity Using DriverQuery.EXE

## ID
9fc3072c-dc8f-4bf7-b231-18950000fadd

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-19

## Tags
attack.discovery

## Description
Detect usage of the "driverquery" utility to perform reconnaissance on installed drivers

## References
https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts/
https://www.vmray.com/cyber-security-blog/analyzing-ursnif-behavior-malware-sandbox/
https://www.fireeye.com/blog/threat-research/2020/01/saigon-mysterious-ursnif-fork.html

## False Positives
Legitimate usage by some scripts might trigger this as well

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "driverquery.exe" AND ((SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\wscript.exe") OR (SrcProcImagePath containsCIS "\AppData\Local\" OR SrcProcImagePath containsCIS "\Users\Public\" OR SrcProcImagePath containsCIS "\Windows\Temp\"))))

```