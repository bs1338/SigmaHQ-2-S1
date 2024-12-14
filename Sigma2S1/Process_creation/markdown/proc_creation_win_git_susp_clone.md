# proc_creation_win_git_susp_clone

## Title
Suspicious Git Clone

## ID
aef9d1f1-7396-4e92-a927-4567c7a495c1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-03

## Tags
attack.reconnaissance, attack.t1593.003

## Description
Detects execution of "git" in order to clone a remote repository that contain suspicious keywords which might be suspicious

## References
https://gist.githubusercontent.com/MichaelKoczwara/12faba9c061c12b5814b711166de8c2f/raw/e2068486692897b620c25fde1ea258c8218fe3d3/history.txt

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " clone " OR TgtProcCmdLine containsCIS "git-remote-https ") AND (TgtProcImagePath endswithCIS "\git.exe" OR TgtProcImagePath endswithCIS "\git-remote-https.exe") AND (TgtProcCmdLine containsCIS "exploit" OR TgtProcCmdLine containsCIS "Vulns" OR TgtProcCmdLine containsCIS "vulnerability" OR TgtProcCmdLine containsCIS "RemoteCodeExecution" OR TgtProcCmdLine containsCIS "Invoke-" OR TgtProcCmdLine containsCIS "CVE-" OR TgtProcCmdLine containsCIS "poc-" OR TgtProcCmdLine containsCIS "ProofOfConcept" OR TgtProcCmdLine containsCIS "proxyshell" OR TgtProcCmdLine containsCIS "log4shell" OR TgtProcCmdLine containsCIS "eternalblue" OR TgtProcCmdLine containsCIS "eternal-blue" OR TgtProcCmdLine containsCIS "MS17-")))

```