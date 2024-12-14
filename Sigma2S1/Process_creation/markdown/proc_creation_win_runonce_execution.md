# proc_creation_win_runonce_execution

## Title
Run Once Task Execution as Configured in Registry

## ID
198effb6-6c98-4d0c-9ea3-451fa143c45c

## Author
Avneet Singh @v3t0_, oscd.community, Christopher Peacock @SecurePeacock (updated)

## Date
2020-10-18

## Tags
attack.defense-evasion, attack.t1112

## Description
This rule detects the execution of Run Once task as configured in the registry

## References
https://twitter.com/pabraeken/status/990717080805789697
https://lolbas-project.github.io/lolbas/Binaries/Runonce/
https://twitter.com/0gtweet/status/1602644163824156672?s=20&t=kuxbUnZPltpvFPZdCrqPXA

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/AlternateShellStartup" OR TgtProcCmdLine endswithCIS "/r") AND (TgtProcImagePath endswithCIS "\runonce.exe" OR TgtProcDisplayName = "Run Once Wrapper")))

```