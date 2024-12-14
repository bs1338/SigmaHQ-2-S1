# proc_creation_win_hktl_adcspwn

## Title
HackTool - ADCSPwn Execution

## ID
cd8c163e-a19b-402e-bdd5-419ff5859f12

## Author
Florian Roth (Nextron Systems)

## Date
2021-07-31

## Tags
attack.credential-access, attack.t1557.001

## Description
Detects command line parameters used by ADCSPwn, a tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service

## References
https://github.com/bats3c/ADCSPwn

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " --adcs " AND TgtProcCmdLine containsCIS " --port "))

```