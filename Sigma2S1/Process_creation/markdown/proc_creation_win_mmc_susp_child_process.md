# proc_creation_win_mmc_susp_child_process

## Title
MMC Spawning Windows Shell

## ID
05a2ab7e-ce11-4b63-86db-ab32e763e11d

## Author
Karneades, Swisscom CSIRT

## Date
2019-08-05

## Tags
attack.lateral-movement, attack.t1021.003

## Description
Detects a Windows command line executable started from MMC

## References
https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/

## False Positives


## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\mmc.exe" AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\reg.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe") OR TgtProcImagePath containsCIS "\BITSADMIN")))

```