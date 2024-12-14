# proc_creation_win_pua_advancedrun

## Title
PUA - AdvancedRun Execution

## ID
d2b749ee-4225-417e-b20e-a8d2193cbb84

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-20

## Tags
attack.execution, attack.defense-evasion, attack.privilege-escalation, attack.t1564.003, attack.t1134.002, attack.t1059.003

## Description
Detects the execution of AdvancedRun utility

## References
https://twitter.com/splinter_code/status/1483815103279603714
https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3
https://www.elastic.co/security-labs/operation-bleeding-bear
https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /EXEFilename " AND TgtProcCmdLine containsCIS " /Run") OR (TgtProcCmdLine containsCIS " /WindowState 0" AND TgtProcCmdLine containsCIS " /RunAs " AND TgtProcCmdLine containsCIS " /CommandLine ")))

```