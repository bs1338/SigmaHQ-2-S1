# proc_creation_win_gpg4win_portable_execution

## Title
Portable Gpg.EXE Execution

## ID
77df53a5-1d78-4f32-bc5a-0e7465bd8f41

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-06

## Tags
attack.impact, attack.t1486

## Description
Detects the execution of "gpg.exe" from uncommon location. Often used by ransomware and loaders to decrypt/encrypt data.

## References
https://www.trendmicro.com/vinfo/vn/threat-encyclopedia/malware/ransom.bat.zarlock.a
https://securelist.com/locked-out/68960/
https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md

## False Positives


## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\gpg.exe" OR TgtProcImagePath endswithCIS "\gpg2.exe") OR TgtProcDisplayName = "GnuPGâ€™s OpenPGP tool") AND (NOT (TgtProcImagePath containsCIS ":\Program Files (x86)\GNU\GnuPG\bin\" OR TgtProcImagePath containsCIS ":\Program Files (x86)\GnuPG VS-Desktop\" OR TgtProcImagePath containsCIS ":\Program Files (x86)\GnuPG\bin\" OR TgtProcImagePath containsCIS ":\Program Files (x86)\Gpg4win\bin\"))))

```