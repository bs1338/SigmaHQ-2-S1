# proc_creation_win_remote_access_tools_meshagent_exec

## Title
Remote Access Tool - MeshAgent Command Execution via MeshCentral

## ID
74a2b202-73e0-4693-9a3a-9d36146d0775

## Author
@Kostastsale

## Date
2024-09-22

## Tags
attack.command-and-control, attack.t1219

## Description
Detects the use of MeshAgent to execute commands on the target host, particularly when threat actors might abuse it to execute commands directly.
MeshAgent can execute commands on the target host by leveraging win-console to obscure their activities and win-dispatcher to run malicious code through IPC with child processes.


## References
https://github.com/Ylianst/MeshAgent
https://github.com/Ylianst/MeshAgent/blob/52cf129ca43d64743181fbaf940e0b4ddb542a37/modules/win-dispatcher.js#L173
https://github.com/Ylianst/MeshAgent/blob/52cf129ca43d64743181fbaf940e0b4ddb542a37/modules/win-info.js#L55

## False Positives
False positives can be found in environments using MessAgent for remote management, analysis should prioritize the grandparent process, MessAgent.exe, and scrutinize the resulting child processes triggered by any suspicious interactive commands directed at the target host.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND SrcProcImagePath endswithCIS "\meshagent.exe"))

```