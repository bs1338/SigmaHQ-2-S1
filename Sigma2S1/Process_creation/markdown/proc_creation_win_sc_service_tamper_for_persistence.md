# proc_creation_win_sc_service_tamper_for_persistence

## Title
Potential Persistence Attempt Via Existing Service Tampering

## ID
38879043-7e1e-47a9-8d46-6bec88e201df

## Author
Sreeman

## Date
2020-09-29

## Tags
attack.persistence, attack.t1543.003, attack.t1574.011

## Description
Detects the modification of an existing service in order to execute an arbitrary payload when the service is started or killed as a potential method for persistence.

## References
https://pentestlab.blog/2020/01/22/persistence-modify-existing-service/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "sc " AND TgtProcCmdLine containsCIS "config " AND TgtProcCmdLine containsCIS "binpath=") OR (TgtProcCmdLine containsCIS "sc " AND TgtProcCmdLine containsCIS "failure" AND TgtProcCmdLine containsCIS "command=")) OR ((TgtProcCmdLine containsCIS ".sh" OR TgtProcCmdLine containsCIS ".exe" OR TgtProcCmdLine containsCIS ".dll" OR TgtProcCmdLine containsCIS ".bin$" OR TgtProcCmdLine containsCIS ".bat" OR TgtProcCmdLine containsCIS ".cmd" OR TgtProcCmdLine containsCIS ".js" OR TgtProcCmdLine containsCIS ".msh$" OR TgtProcCmdLine containsCIS ".reg$" OR TgtProcCmdLine containsCIS ".scr" OR TgtProcCmdLine containsCIS ".ps" OR TgtProcCmdLine containsCIS ".vb" OR TgtProcCmdLine containsCIS ".jar" OR TgtProcCmdLine containsCIS ".pl") AND ((TgtProcCmdLine containsCIS "reg " AND TgtProcCmdLine containsCIS "add " AND TgtProcCmdLine containsCIS "FailureCommand") OR (TgtProcCmdLine containsCIS "reg " AND TgtProcCmdLine containsCIS "add " AND TgtProcCmdLine containsCIS "ImagePath")))))

```