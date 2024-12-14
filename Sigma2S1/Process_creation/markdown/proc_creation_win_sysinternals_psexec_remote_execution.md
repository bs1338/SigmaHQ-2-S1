# proc_creation_win_sysinternals_psexec_remote_execution

## Title
Potential PsExec Remote Execution

## ID
ea011323-7045-460b-b2d7-0f7442ea6b38

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-28

## Tags
attack.resource-development, attack.t1587.001

## Description
Detects potential psexec command that initiate execution on a remote systems via common commandline flags used by the utility

## References
https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
https://www.poweradmin.com/paexec/
https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "accepteula" AND TgtProcCmdLine containsCIS " -u " AND TgtProcCmdLine containsCIS " -p " AND TgtProcCmdLine containsCIS " \\"))

```