# proc_creation_win_hktl_koadic

## Title
HackTool - Koadic Execution

## ID
5cddf373-ef00-4112-ad72-960ac29bac34

## Author
wagga, Jonhnathan Ribeiro, oscd.community

## Date
2020-01-12

## Tags
attack.execution, attack.t1059.003, attack.t1059.005, attack.t1059.007

## Description
Detects command line parameters used by Koadic hack tool

## References
https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/
https://github.com/offsecginger/koadic/blob/457f9a3ff394c989cdb4c599ab90eb34fb2c762c/data/stager/js/stdlib.js
https://blog.f-secure.com/hunting-for-koadic-a-com-based-rootkit/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/q" AND TgtProcCmdLine containsCIS "/c" AND TgtProcCmdLine containsCIS "chcp") AND TgtProcImagePath endswithCIS "\cmd.exe"))

```