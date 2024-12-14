# proc_creation_win_mshta_susp_child_processes

## Title
Suspicious MSHTA Child Process

## ID
03cc0c25-389f-4bf8-b48d-11878079f1ca

## Author
Michael Haag

## Date
2019-01-16

## Tags
attack.defense-evasion, attack.t1218.005, car.2013-02-003, car.2013-03-001, car.2014-04-003

## Description
Detects a suspicious process spawning from an "mshta.exe" process, which could be indicative of a malicious HTA script execution

## References
https://www.trustedsec.com/july-2015/malicious-htas/

## False Positives
Printer software / driver installations
HP software

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\reg.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe") AND SrcProcImagePath endswithCIS "\mshta.exe"))

```