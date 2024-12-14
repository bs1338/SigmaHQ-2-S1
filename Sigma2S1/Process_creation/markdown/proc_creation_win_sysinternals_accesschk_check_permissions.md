# proc_creation_win_sysinternals_accesschk_check_permissions

## Title
Permission Check Via Accesschk.EXE

## ID
c625d754-6a3d-4f65-9c9a-536aea960d37

## Author
Teymur Kheirkhabarov (idea), Mangatas Tondang, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2020-10-13

## Tags
attack.discovery, attack.t1069.001

## Description
Detects the usage of the "Accesschk" utility, an access and privilege audit tool developed by SysInternal and often being abused by attacker to verify process privileges

## References
https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment?slide=43
https://www.youtube.com/watch?v=JGs-aKf2OtU&ab_channel=OFFZONEMOSCOW
https://github.com/carlospolop/PEASS-ng/blob/fa0f2e17fbc1d86f1fd66338a40e665e7182501d/winPEAS/winPEASbat/winPEAS.bat
https://github.com/gladiatx0r/Powerless/blob/04f553bbc0c65baf4e57344deff84e3f016e6b51/Powerless.bat

## False Positives
System administrator Usage

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "uwcqv " OR TgtProcCmdLine containsCIS "kwsu " OR TgtProcCmdLine containsCIS "qwsu " OR TgtProcCmdLine containsCIS "uwdqs ") AND (TgtProcDisplayName endswithCIS "AccessChk" OR TgtProcDisplayName containsCIS "Reports effective permissions" OR (TgtProcImagePath endswithCIS "\accesschk.exe" OR TgtProcImagePath endswithCIS "\accesschk64.exe"))))

```