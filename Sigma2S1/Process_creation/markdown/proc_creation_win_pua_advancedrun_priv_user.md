# proc_creation_win_pua_advancedrun_priv_user

## Title
PUA - AdvancedRun Suspicious Execution

## ID
fa00b701-44c6-4679-994d-5a18afa8a707

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-20

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1134.002

## Description
Detects the execution of AdvancedRun utility in the context of the TrustedInstaller, SYSTEM, Local Service or Network Service accounts

## References
https://twitter.com/splinter_code/status/1483815103279603714
https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3
https://www.elastic.co/security-labs/operation-bleeding-bear
https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/EXEFilename" OR TgtProcCmdLine containsCIS "/CommandLine") AND ((TgtProcCmdLine containsCIS " /RunAs 8 " OR TgtProcCmdLine containsCIS " /RunAs 4 " OR TgtProcCmdLine containsCIS " /RunAs 10 " OR TgtProcCmdLine containsCIS " /RunAs 11 ") OR (TgtProcCmdLine endswithCIS "/RunAs 8" OR TgtProcCmdLine endswithCIS "/RunAs 4" OR TgtProcCmdLine endswithCIS "/RunAs 10" OR TgtProcCmdLine endswithCIS "/RunAs 11"))))

```