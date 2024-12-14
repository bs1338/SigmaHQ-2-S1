# proc_creation_win_java_remote_debugging

## Title
Java Running with Remote Debugging

## ID
8f88e3f6-2a49-48f5-a5c4-2f7eedf78710

## Author
Florian Roth (Nextron Systems)

## Date
2019-01-16

## Tags
attack.t1203, attack.execution

## Description
Detects a JAVA process running with remote debugging allowing more than just localhost to connect

## References
https://dzone.com/articles/remote-debugging-java-applications-with-jdwp

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "transport=dt_socket,address=" AND (TgtProcCmdLine containsCIS "jre1." OR TgtProcCmdLine containsCIS "jdk1.")) AND (NOT (TgtProcCmdLine containsCIS "address=127.0.0.1" OR TgtProcCmdLine containsCIS "address=localhost"))))

```