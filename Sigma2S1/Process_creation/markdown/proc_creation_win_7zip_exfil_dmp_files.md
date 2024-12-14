# proc_creation_win_7zip_exfil_dmp_files

## Title
7Zip Compressing Dump Files

## ID
ec570e53-4c76-45a9-804d-dc3f355ff7a7

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-27

## Tags
attack.collection, attack.t1560.001

## Description
Detects execution of 7z in order to compress a file with a ".dmp"/".dump" extension, which could be a step in a process of dump file exfiltration.

## References
https://thedfirreport.com/2022/09/26/bumblebee-round-two/

## False Positives
Legitimate use of 7z with a command line in which ".dmp" or ".dump" appears accidentally
Legitimate use of 7z to compress WER ".dmp" files for troubleshooting

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".dmp" OR TgtProcCmdLine containsCIS ".dump" OR TgtProcCmdLine containsCIS ".hdmp") AND (TgtProcDisplayName containsCIS "7-Zip" OR (TgtProcImagePath endswithCIS "\7z.exe" OR TgtProcImagePath endswithCIS "\7zr.exe" OR TgtProcImagePath endswithCIS "\7za.exe"))))

```