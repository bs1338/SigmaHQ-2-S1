# proc_creation_win_hktl_sharp_impersonation

## Title
HackTool - SharpImpersonation Execution

## ID
f89b08d0-77ad-4728-817b-9b16c5a69c7a

## Author
Sai Prashanth Pulisetti @pulisettis, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-27

## Tags
attack.privilege-escalation, attack.defense-evasion, attack.t1134.001, attack.t1134.003

## Description
Detects execution of the SharpImpersonation tool. Which can be used to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively

## References
https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/
https://github.com/S3cur3Th1sSh1t/SharpImpersonation

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " user:" AND TgtProcCmdLine containsCIS " binary:") OR (TgtProcCmdLine containsCIS " user:" AND TgtProcCmdLine containsCIS " shellcode:") OR (TgtProcCmdLine containsCIS " technique:CreateProcessAsUserW" OR TgtProcCmdLine containsCIS " technique:ImpersonateLoggedOnuser")) OR TgtProcImagePath endswithCIS "\SharpImpersonation.exe"))

```