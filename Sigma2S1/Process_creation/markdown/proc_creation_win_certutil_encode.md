# proc_creation_win_certutil_encode

## Title
File Encoded To Base64 Via Certutil.EXE

## ID
e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a

## Author
Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-02-24

## Tags
attack.defense-evasion, attack.t1027

## Description
Detects the execution of certutil with the "encode" flag to encode a file to base64. This can be abused by threat actors and attackers for data exfiltration

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/
https://lolbas-project.github.io/lolbas/Binaries/Certutil/

## False Positives
As this is a general purpose rule, legitimate usage of the encode functionality will trigger some false positives. Apply additional filters accordingly

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-encode" OR TgtProcCmdLine containsCIS "/encode" OR TgtProcCmdLine containsCIS "â€“encode" OR TgtProcCmdLine containsCIS "â€”encode" OR TgtProcCmdLine containsCIS "â€•encode") AND TgtProcImagePath endswithCIS "\certutil.exe"))

```