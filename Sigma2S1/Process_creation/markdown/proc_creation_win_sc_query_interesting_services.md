# proc_creation_win_sc_query_interesting_services

## Title
Interesting Service Enumeration Via Sc.EXE

## ID
e83e8899-c9b2-483b-b355-5decc942b959

## Author
Swachchhanda Shrawan Poudel

## Date
2024-02-12

## Tags
attack.t1003

## Description
Detects the enumeration and query of interesting and in some cases sensitive services on the system via "sc.exe".
Attackers often try to enumerate the services currently running on a system in order to find different attack vectors.


## References
https://www.n00py.io/2021/05/dumping-plaintext-rdp-credentials-from-svchost-exe/
https://pentestlab.blog/tag/svchost/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "query" AND TgtProcCmdLine containsCIS "termservice" AND TgtProcImagePath endswithCIS "\sc.exe"))

```