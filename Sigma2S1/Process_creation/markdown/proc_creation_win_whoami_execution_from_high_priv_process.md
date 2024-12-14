# proc_creation_win_whoami_execution_from_high_priv_process

## Title
Whoami.EXE Execution From Privileged Process

## ID
79ce34ca-af29-4d0e-b832-fc1b377020db

## Author
Florian Roth (Nextron Systems), Teymur Kheirkhabarov

## Date
2022-01-28

## Tags
attack.privilege-escalation, attack.discovery, attack.t1033

## Description
Detects the execution of "whoami.exe" by privileged accounts that are often abused by threat actors

## References
https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
https://web.archive.org/web/20221019044836/https://nsudo.m2team.org/en-us/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\whoami.exe" AND (TgtProcUser containsCIS "AUTHORI" OR TgtProcUser containsCIS "AUTORI" OR TgtProcUser containsCIS "TrustedInstaller")))

```