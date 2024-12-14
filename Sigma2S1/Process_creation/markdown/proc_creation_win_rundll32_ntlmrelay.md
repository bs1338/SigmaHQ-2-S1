# proc_creation_win_rundll32_ntlmrelay

## Title
Suspicious NTLM Authentication on the Printer Spooler Service

## ID
bb76d96b-821c-47cf-944b-7ce377864492

## Author
Elastic (idea), Tobias Michalski (Nextron Systems)

## Date
2022-05-04

## Tags
attack.privilege-escalation, attack.credential-access, attack.t1212

## Description
Detects a privilege elevation attempt by coercing NTLM authentication on the Printer Spooler service

## References
https://twitter.com/med0x2e/status/1520402518685200384
https://github.com/elastic/detection-rules/blob/dd224fb3f81d0b4bf8593c5f02a029d647ba2b2d/rules/windows/credential_access_relay_ntlm_auth_via_http_spoolss.toml

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "spoolss" OR TgtProcCmdLine containsCIS "srvsvc" OR TgtProcCmdLine containsCIS "/print/pipe/") AND (TgtProcCmdLine containsCIS "C:\windows\system32\davclnt.dll,DavSetCookie" AND TgtProcCmdLine containsCIS "http")) AND TgtProcImagePath endswithCIS "\rundll32.exe"))

```