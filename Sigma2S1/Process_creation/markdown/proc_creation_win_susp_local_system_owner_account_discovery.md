# proc_creation_win_susp_local_system_owner_account_discovery

## Title
Local Accounts Discovery

## ID
502b42de-4306-40b4-9596-6f590c81f073

## Author
Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community

## Date
2019-10-21

## Tags
attack.discovery, attack.t1033, attack.t1087.001

## Description
Local accounts, System Owner/User discovery using operating systems utilities

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1033/T1033.md

## False Positives
Legitimate administrator or user enumerates local users for legitimate reason

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcCmdLine containsCIS " /c" AND TgtProcCmdLine containsCIS "dir " AND TgtProcCmdLine containsCIS "\Users\") AND TgtProcImagePath endswithCIS "\cmd.exe") AND (NOT TgtProcCmdLine containsCIS " rmdir ")) OR ((TgtProcCmdLine containsCIS "user" AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")) AND (NOT (TgtProcCmdLine containsCIS "/domain" OR TgtProcCmdLine containsCIS "/add" OR TgtProcCmdLine containsCIS "/delete" OR TgtProcCmdLine containsCIS "/active" OR TgtProcCmdLine containsCIS "/expires" OR TgtProcCmdLine containsCIS "/passwordreq" OR TgtProcCmdLine containsCIS "/scriptpath" OR TgtProcCmdLine containsCIS "/times" OR TgtProcCmdLine containsCIS "/workstations"))) OR ((TgtProcCmdLine containsCIS " /l" AND TgtProcImagePath endswithCIS "\cmdkey.exe") OR (TgtProcImagePath endswithCIS "\whoami.exe" OR TgtProcImagePath endswithCIS "\quser.exe" OR TgtProcImagePath endswithCIS "\qwinsta.exe") OR ((TgtProcCmdLine containsCIS "useraccount" AND TgtProcCmdLine containsCIS "get") AND TgtProcImagePath endswithCIS "\wmic.exe"))))

```