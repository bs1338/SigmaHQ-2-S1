# proc_creation_win_susp_add_user_local_admin_group

## Title
User Added to Local Administrators Group

## ID
ad720b90-25ad-43ff-9b5e-5c841facc8e5

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-12

## Tags
attack.persistence, attack.t1098

## Description
Detects addition of users to the local administrator group via "Net" or "Add-LocalGroupMember".

## References
https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html?m=1

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " administrators " OR TgtProcCmdLine containsCIS " administrateur") AND ((TgtProcCmdLine containsCIS "localgroup " AND TgtProcCmdLine containsCIS " /add") OR (TgtProcCmdLine containsCIS "Add-LocalGroupMember " AND TgtProcCmdLine containsCIS " -Group "))))

```