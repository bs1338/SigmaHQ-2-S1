# proc_creation_win_addinutil_suspicious_cmdline

## Title
Suspicious AddinUtil.EXE CommandLine Execution

## ID
631b22a4-70f4-4e2f-9ea8-42f84d9df6d8

## Author
Nasreddine Bencherchali (Nextron Systems), Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)

## Date
2023-09-18

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) with suspicious Addinroot or Pipelineroot paths. An adversary may execute AddinUtil.exe with uncommon Addinroot/Pipelineroot paths that point to the adversaries Addins.Store payload.


## References
https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\addinutil.exe" AND (((TgtProcCmdLine containsCIS "-AddInRoot:" OR TgtProcCmdLine containsCIS "-PipelineRoot:") AND (TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "\Downloads\" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "\Windows\Temp\")) OR ((TgtProcCmdLine containsCIS "-AddInRoot:." OR TgtProcCmdLine containsCIS "-AddInRoot:\".\"" OR TgtProcCmdLine containsCIS "-PipelineRoot:." OR TgtProcCmdLine containsCIS "-PipelineRoot:\".\"") AND (TgtProcImagePath containsCIS "\AppData\Local\Temp\" OR TgtProcImagePath containsCIS "\Desktop\" OR TgtProcImagePath containsCIS "\Downloads\" OR TgtProcImagePath containsCIS "\Users\Public\" OR TgtProcImagePath containsCIS "\Windows\Temp\")))))

```