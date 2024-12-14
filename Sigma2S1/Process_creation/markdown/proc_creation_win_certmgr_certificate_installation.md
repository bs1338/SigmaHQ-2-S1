# proc_creation_win_certmgr_certificate_installation

## Title
New Root Certificate Installed Via CertMgr.EXE

## ID
ff992eac-6449-4c60-8c1d-91c9722a1d48

## Author
oscd.community, @redcanary, Zach Stanford @svch0st

## Date
2023-03-05

## Tags
attack.defense-evasion, attack.t1553.004

## Description
Detects execution of "certmgr" with the "add" flag in order to install a new certificate on the system.
Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md
https://securelist.com/to-crypt-or-to-mine-that-is-the-question/86307/

## False Positives
Help Desk or IT may need to manually add a corporate Root CA on occasion. Need to test if GPO push doesn't trigger FP

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/add" AND TgtProcCmdLine containsCIS "root") AND TgtProcImagePath endswithCIS "\CertMgr.exe"))

```