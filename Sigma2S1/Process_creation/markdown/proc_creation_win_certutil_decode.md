# proc_creation_win_certutil_decode

## Title
File Decoded From Base64/Hex Via Certutil.EXE

## ID
cc9cbe82-7bc0-4ef5-bc23-bbfb83947be7

## Author
Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community

## Date
2023-02-15

## Tags
attack.defense-evasion, attack.t1027

## Description
Detects the execution of certutil with either the "decode" or "decodehex" flags to decode base64 or hex encoded files. This can be abused by attackers to decode an encoded payload before execution

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/
https://news.sophos.com/en-us/2021/04/13/compromised-exchange-server-hosting-cryptojacker-targeting-other-exchange-servers/
https://twitter.com/JohnLaTwC/status/835149808817991680
https://learn.microsoft.com/en-us/archive/blogs/pki/basic-crl-checking-with-certutil
https://lolbas-project.github.io/lolbas/Binaries/Certutil/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-decode " OR TgtProcCmdLine containsCIS "/decode " OR TgtProcCmdLine containsCIS "â€“decode " OR TgtProcCmdLine containsCIS "â€”decode " OR TgtProcCmdLine containsCIS "â€•decode " OR TgtProcCmdLine containsCIS "-decodehex " OR TgtProcCmdLine containsCIS "/decodehex " OR TgtProcCmdLine containsCIS "â€“decodehex " OR TgtProcCmdLine containsCIS "â€”decodehex " OR TgtProcCmdLine containsCIS "â€•decodehex ") AND TgtProcImagePath endswithCIS "\certutil.exe"))

```