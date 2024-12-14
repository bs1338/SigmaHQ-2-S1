# proc_creation_win_susp_privilege_escalation_cli_patterns

## Title
Suspicious RunAs-Like Flag Combination

## ID
50d66fb0-03f8-4da0-8add-84e77d12a020

## Author
Florian Roth (Nextron Systems)

## Date
2022-11-11

## Tags
attack.privilege-escalation

## Description
Detects suspicious command line flags that let the user set a target user and command as e.g. seen in PsExec-like tools

## References
https://www.trendmicro.com/en_us/research/22/k/hack-the-real-box-apt41-new-subgroup-earth-longzhi.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -c cmd" OR TgtProcCmdLine containsCIS " -c \"cmd" OR TgtProcCmdLine containsCIS " -c powershell" OR TgtProcCmdLine containsCIS " -c \"powershell" OR TgtProcCmdLine containsCIS " --command cmd" OR TgtProcCmdLine containsCIS " --command powershell" OR TgtProcCmdLine containsCIS " -c whoami" OR TgtProcCmdLine containsCIS " -c wscript" OR TgtProcCmdLine containsCIS " -c cscript") AND (TgtProcCmdLine containsCIS " -u system " OR TgtProcCmdLine containsCIS " --user system " OR TgtProcCmdLine containsCIS " -u NT" OR TgtProcCmdLine containsCIS " -u \"NT" OR TgtProcCmdLine containsCIS " -u 'NT" OR TgtProcCmdLine containsCIS " --system " OR TgtProcCmdLine containsCIS " -u administrator ")))

```