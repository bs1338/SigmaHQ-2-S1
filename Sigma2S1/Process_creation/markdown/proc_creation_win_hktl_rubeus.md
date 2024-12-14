# proc_creation_win_hktl_rubeus

## Title
HackTool - Rubeus Execution

## ID
7ec2c172-dceb-4c10-92c9-87c1881b7e18

## Author
Florian Roth (Nextron Systems)

## Date
2018-12-19

## Tags
attack.credential-access, attack.t1003, attack.t1558.003, attack.lateral-movement, attack.t1550.003

## Description
Detects the execution of the hacktool Rubeus via PE information of command line parameters

## References
https://blog.harmj0y.net/redteaming/from-kekeo-to-rubeus
https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html
https://github.com/GhostPack/Rubeus

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\Rubeus.exe" OR TgtProcDisplayName = "Rubeus" OR (TgtProcCmdLine containsCIS "asreproast " OR TgtProcCmdLine containsCIS "dump /service:krbtgt " OR TgtProcCmdLine containsCIS "dump /luid:0x" OR TgtProcCmdLine containsCIS "kerberoast " OR TgtProcCmdLine containsCIS "createnetonly /program:" OR TgtProcCmdLine containsCIS "ptt /ticket:" OR TgtProcCmdLine containsCIS "/impersonateuser:" OR TgtProcCmdLine containsCIS "renew /ticket:" OR TgtProcCmdLine containsCIS "asktgt /user:" OR TgtProcCmdLine containsCIS "harvest /interval:" OR TgtProcCmdLine containsCIS "s4u /user:" OR TgtProcCmdLine containsCIS "s4u /ticket:" OR TgtProcCmdLine containsCIS "hash /password:" OR TgtProcCmdLine containsCIS "golden /aes256:" OR TgtProcCmdLine containsCIS "silver /user:")))

```