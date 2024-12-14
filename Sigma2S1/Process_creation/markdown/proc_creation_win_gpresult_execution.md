# proc_creation_win_gpresult_execution

## Title
Gpresult Display Group Policy Information

## ID
e56d3073-83ff-4021-90fe-c658e0709e72

## Author
frack113

## Date
2022-05-01

## Tags
attack.discovery, attack.t1615

## Description
Detects cases in which a user uses the built-in Windows utility gpresult to display the Resultant Set of Policy (RSoP) information

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1615/T1615.md
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult
https://unit42.paloaltonetworks.com/emissary-trojan-changelog-did-operation-lotus-blossom-cause-it-to-evolve/
https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/z" OR TgtProcCmdLine containsCIS "/v") AND TgtProcImagePath endswithCIS "\gpresult.exe"))

```