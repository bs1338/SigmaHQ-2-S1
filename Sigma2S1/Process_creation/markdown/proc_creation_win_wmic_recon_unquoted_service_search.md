# proc_creation_win_wmic_recon_unquoted_service_search

## Title
Potential Unquoted Service Path Reconnaissance Via Wmic.EXE

## ID
68bcd73b-37ef-49cb-95fc-edc809730be6

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-20

## Tags
attack.execution, attack.t1047

## Description
Detects known WMI recon method to look for unquoted service paths using wmic. Often used by pentester and attacker enumeration scripts

## References
https://github.com/nccgroup/redsnarf/blob/35949b30106ae543dc6f2bc3f1be10c6d9a8d40e/redsnarf.py
https://github.com/S3cur3Th1sSh1t/Creds/blob/eac23d67f7f90c7fc8e3130587d86158c22aa398/PowershellScripts/jaws-enum.ps1
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " service get " AND TgtProcCmdLine containsCIS "name,displayname,pathname,startmode") AND TgtProcImagePath endswithCIS "\WMIC.exe"))

```