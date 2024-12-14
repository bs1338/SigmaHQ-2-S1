# proc_creation_win_lolbin_manage_bde

## Title
Potential Manage-bde.wsf Abuse To Proxy Execution

## ID
c363385c-f75d-4753-a108-c1a8e28bdbda

## Author
oscd.community, Natalia Shornikova, Nasreddine Bencherchali (Nextron Systems)

## Date
2020-10-13

## Tags
attack.defense-evasion, attack.t1216

## Description
Detects potential abuse of the "manage-bde.wsf" script as a LOLBIN to proxy execution

## References
https://lolbas-project.github.io/lolbas/Scripts/Manage-bde/
https://gist.github.com/bohops/735edb7494fe1bd1010d67823842b712
https://twitter.com/bohops/status/980659399495741441
https://twitter.com/JohnLaTwC/status/1223292479270600706
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1216/T1216.md

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "manage-bde.wsf" AND TgtProcImagePath endswithCIS "\wscript.exe") OR ((SrcProcCmdLine containsCIS "manage-bde.wsf" AND (SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\wscript.exe")) AND (NOT TgtProcImagePath endswithCIS "\cmd.exe"))))

```