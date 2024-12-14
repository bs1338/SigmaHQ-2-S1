# proc_creation_win_node_abuse

## Title
Potential Arbitrary Code Execution Via Node.EXE

## ID
6640f31c-01ad-49b5-beb5-83498a5cd8bd

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-09

## Tags
attack.defense-evasion, attack.t1127

## Description
Detects the execution node.exe which is shipped with multiple software such as VMware, Adobe...etc. In order to execute arbitrary code. For example to establish reverse shell as seen in Log4j attacks...etc

## References
http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
https://www.sprocketsecurity.com/resources/crossing-the-log4j-horizon-a-vulnerability-with-no-return
https://www.rapid7.com/blog/post/2022/01/18/active-exploitation-of-vmware-horizon-servers/
https://nodejs.org/api/cli.html

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -e " OR TgtProcCmdLine containsCIS " --eval ") AND TgtProcImagePath endswithCIS "\node.exe") AND (TgtProcCmdLine containsCIS ".exec(" AND TgtProcCmdLine containsCIS "net.socket" AND TgtProcCmdLine containsCIS ".connect" AND TgtProcCmdLine containsCIS "child_process")))

```