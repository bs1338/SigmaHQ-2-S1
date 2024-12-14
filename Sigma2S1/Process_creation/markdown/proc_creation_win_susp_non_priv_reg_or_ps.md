# proc_creation_win_susp_non_priv_reg_or_ps

## Title
Non-privileged Usage of Reg or Powershell

## ID
8f02c935-effe-45b3-8fc9-ef8696a9e41d

## Author
Teymur Kheirkhabarov (idea), Ryan Plas (rule), oscd.community

## Date
2020-10-05

## Tags
attack.defense-evasion, attack.t1112

## Description
Search for usage of reg or Powershell by non-privileged users to modify service configuration in registry

## References
https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-20-638.jpg

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "reg " AND TgtProcCmdLine containsCIS "add") OR (TgtProcCmdLine containsCIS "powershell" OR TgtProcCmdLine containsCIS "set-itemproperty" OR TgtProcCmdLine containsCIS " sp " OR TgtProcCmdLine containsCIS "new-itemproperty")) AND ((TgtProcCmdLine containsCIS "ImagePath" OR TgtProcCmdLine containsCIS "FailureCommand" OR TgtProcCmdLine containsCIS "ServiceDLL") AND (TgtProcCmdLine containsCIS "ControlSet" AND TgtProcCmdLine containsCIS "Services") AND (TgtProcIntegrityLevel In ("Medium","S-1-16-8192")))))

```