# proc_creation_win_cmdkey_recon

## Title
Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE

## ID
07f8bdc2-c9b3-472a-9817-5a670b872f53

## Author
jmallette, Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2019-01-16

## Tags
attack.credential-access, attack.t1003.005

## Description
Detects usage of cmdkey to look for cached credentials on the system

## References
https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation
https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx
https://github.com/redcanaryco/atomic-red-team/blob/b27a3cb25025161d49ac861cb216db68c46a3537/atomics/T1003.005/T1003.005.md#atomic-test-1---cached-credential-dump-via-cmdkey

## False Positives
Legitimate administrative tasks

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -l" OR TgtProcCmdLine containsCIS " /l" OR TgtProcCmdLine containsCIS " â€“l" OR TgtProcCmdLine containsCIS " â€”l" OR TgtProcCmdLine containsCIS " â€•l") AND TgtProcImagePath endswithCIS "\cmdkey.exe"))

```