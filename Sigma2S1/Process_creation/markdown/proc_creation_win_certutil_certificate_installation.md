# proc_creation_win_certutil_certificate_installation

## Title
New Root Certificate Installed Via Certutil.EXE

## ID
d2125259-ddea-4c1c-9c22-977eb5b29cf0

## Author
oscd.community, @redcanary, Zach Stanford @svch0st

## Date
2023-03-05

## Tags
attack.defense-evasion, attack.t1553.004

## Description
Detects execution of "certutil" with the "addstore" flag in order to install a new certificate on the system.
Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md

## False Positives
Help Desk or IT may need to manually add a corporate Root CA on occasion. Need to test if GPO push doesn't trigger FP

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-addstore" OR TgtProcCmdLine containsCIS "/addstore" OR TgtProcCmdLine containsCIS "â€“addstore" OR TgtProcCmdLine containsCIS "â€”addstore" OR TgtProcCmdLine containsCIS "â€•addstore") AND TgtProcCmdLine containsCIS "root" AND TgtProcImagePath endswithCIS "\certutil.exe"))

```