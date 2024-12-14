# proc_creation_win_addinutil_uncommon_cmdline

## Title
Uncommon AddinUtil.EXE CommandLine Execution

## ID
4f2cd9b6-4a17-440f-bb2a-687abb65993a

## Author
Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)

## Date
2023-09-18

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) with uncommon Addinroot or Pipelineroot paths. An adversary may execute AddinUtil.exe with uncommon Addinroot/Pipelineroot paths that point to the adversaries Addins.Store payload.


## References
https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "-AddInRoot:" OR TgtProcCmdLine containsCIS "-PipelineRoot:") AND TgtProcImagePath endswithCIS "\addinutil.exe") AND (NOT (TgtProcCmdLine containsCIS "-AddInRoot:\"C:\Program Files (x86)\Common Files\Microsoft Shared\VSTA" OR TgtProcCmdLine containsCIS "-AddInRoot:C:\Program Files (x86)\Common Files\Microsoft Shared\VSTA" OR TgtProcCmdLine containsCIS "-PipelineRoot:\"C:\Program Files (x86)\Common Files\Microsoft Shared\VSTA" OR TgtProcCmdLine containsCIS "-PipelineRoot:C:\Program Files (x86)\Common Files\Microsoft Shared\VSTA"))))

```