# proc_creation_win_susp_lolbin_exec_from_non_c_drive

## Title
LOLBIN Execution From Abnormal Drive

## ID
d4ca7c59-e9e4-42d8-bf57-91a776efcb87

## Author
Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Angelo Violetti - SEC Consult '@angelo_violetti', Aaron Herman

## Date
2022-01-25

## Tags
attack.defense-evasion

## Description
Detects LOLBINs executing from an abnormal or uncommon drive such as a mounted ISO.

## References
https://thedfirreport.com/2021/12/13/diavol-ransomware/
https://www.scythe.io/library/threat-emulation-qakbot
https://sec-consult.com/blog/detail/bumblebee-hunting-with-a-velociraptor/

## False Positives
Rare false positives could occur on servers with multiple drives.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\calc.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cmstp.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\installutil.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND (NOT (TgtProcImagePath containsCIS "C:\" OR TgtProcImagePath = "" OR TgtProcImagePath IS NOT EMPTY))))

```