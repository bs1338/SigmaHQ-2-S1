# proc_creation_win_rundll32_process_dump_via_comsvcs

## Title
Process Memory Dump Via Comsvcs.DLL

## ID
646ea171-dded-4578-8a4d-65e9822892e3

## Author
Florian Roth (Nextron Systems), Modexp, Nasreddine Bencherchali (Nextron Systems)

## Date
2020-02-18

## Tags
attack.defense-evasion, attack.credential-access, attack.t1036, attack.t1003.001, car.2013-05-009

## Description
Detects a process memory dump via "comsvcs.dll" using rundll32, covering multiple different techniques (ordinal, minidump function, etc.)

## References
https://twitter.com/shantanukhande/status/1229348874298388484
https://twitter.com/pythonresponder/status/1385064506049630211?s=21
https://twitter.com/Hexacorn/status/1224848930795552769
https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
https://twitter.com/SBousseaden/status/1167417096374050817
https://twitter.com/Wietze/status/1542107456507203586
https://github.com/Hackndo/lsassy/blob/14d8f8ae596ecf22b449bfe919829173b8a07635/lsassy/dumpmethod/comsvcs.py

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcCmdLine containsCIS "rundll32") AND ((TgtProcCmdLine containsCIS "#-" OR TgtProcCmdLine containsCIS "#+" OR TgtProcCmdLine containsCIS "#24" OR TgtProcCmdLine containsCIS "24 " OR TgtProcCmdLine containsCIS "MiniDump") AND (TgtProcCmdLine containsCIS "comsvcs" AND TgtProcCmdLine containsCIS "full"))) OR ((TgtProcCmdLine containsCIS " #" OR TgtProcCmdLine containsCIS ",#" OR TgtProcCmdLine containsCIS ", #") AND (TgtProcCmdLine containsCIS "24" AND TgtProcCmdLine containsCIS "comsvcs" AND TgtProcCmdLine containsCIS "full"))))

```