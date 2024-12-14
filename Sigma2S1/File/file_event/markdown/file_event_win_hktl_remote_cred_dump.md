# file_event_win_hktl_remote_cred_dump

## Title
HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump

## ID
6e2a900a-ced9-4e4a-a9c2-13e706f9518a

## Author
SecurityAura

## Date
2022-11-16

## Tags
attack.credential-access, attack.t1003

## Description
Detects default filenames output from the execution of CrackMapExec and Impacket-secretsdump against an endpoint.

## References
https://github.com/Porchetta-Industries/CrackMapExec
https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\svchost.exe" AND TgtFilePath RegExp "\\\\Windows\\\\System32\\\\[a-zA-Z0-9]{8}\\.tmp$"))

```