# proc_creation_win_forfiles_proxy_execution_

## Title
Forfiles Command Execution

## ID
9aa5106d-bce3-4b13-86df-3a20f1d5cf0b

## Author
Tim Rauch, Elastic, E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community

## Date
2022-06-14

## Tags
attack.execution, attack.t1059

## Description
Detects the execution of "forfiles" with the "/c" flag.
While this is an expected behavior of the tool, it can be abused in order to proxy execution through it with any binary.
Can be used to bypass application whitelisting.


## References
https://lolbas-project.github.io/lolbas/Binaries/Forfiles/
https://pentestlab.blog/2020/07/06/indirect-command-execution/

## False Positives
Legitimate use via a batch script or by an administrator.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -c " OR TgtProcCmdLine containsCIS " /c " OR TgtProcCmdLine containsCIS " â€“c " OR TgtProcCmdLine containsCIS " â€”c " OR TgtProcCmdLine containsCIS " â€•c ") AND TgtProcImagePath endswithCIS "\forfiles.exe"))

```