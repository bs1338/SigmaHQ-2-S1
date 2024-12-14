# proc_creation_win_pdqdeploy_runner_susp_children

## Title
Potentially Suspicious Execution Of PDQDeployRunner

## ID
12b8e9f5-96b2-41e1-9a42-8c6779a5c184

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-22

## Tags
attack.execution

## Description
Detects suspicious execution of "PDQDeployRunner" which is part of the PDQDeploy service stack that is responsible for executing commands and packages on a remote machines

## References
https://twitter.com/malmoeb/status/1550483085472432128

## False Positives
Legitimate use of the PDQDeploy tool to execute these commands

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\csc.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\dllhost.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\scriptrunner.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\wsl.exe") OR (TgtProcImagePath containsCIS ":\ProgramData\" OR TgtProcImagePath containsCIS ":\Users\Public\" OR TgtProcImagePath containsCIS ":\Windows\TEMP\" OR TgtProcImagePath containsCIS "\AppData\Local\Temp") OR (TgtProcCmdLine containsCIS " -decode " OR TgtProcCmdLine containsCIS " -enc " OR TgtProcCmdLine containsCIS " -encodedcommand " OR TgtProcCmdLine containsCIS " -w hidden" OR TgtProcCmdLine containsCIS "DownloadString" OR TgtProcCmdLine containsCIS "FromBase64String" OR TgtProcCmdLine containsCIS "http" OR TgtProcCmdLine containsCIS "iex " OR TgtProcCmdLine containsCIS "Invoke-")) AND SrcProcImagePath containsCIS "\PDQDeployRunner-"))

```