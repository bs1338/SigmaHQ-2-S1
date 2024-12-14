# proc_creation_win_susp_add_user_privileged_group

## Title
User Added To Highly Privileged Group

## ID
10fb649c-3600-4d37-b1e6-56ea90bb7e09

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-02-23

## Tags
attack.persistence, attack.t1098

## Description
Detects addition of users to highly privileged groups via "Net" or "Add-LocalGroupMember".

## References
https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## False Positives
Administrative activity that must be investigated

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Group Policy Creator Owners" OR TgtProcCmdLine containsCIS "Schema Admins") AND ((TgtProcCmdLine containsCIS "localgroup " AND TgtProcCmdLine containsCIS " /add") OR (TgtProcCmdLine containsCIS "Add-LocalGroupMember " AND TgtProcCmdLine containsCIS " -Group "))))

```