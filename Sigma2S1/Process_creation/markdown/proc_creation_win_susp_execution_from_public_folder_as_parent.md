# proc_creation_win_susp_execution_from_public_folder_as_parent

## Title
Potentially Suspicious Execution From Parent Process In Public Folder

## ID
69bd9b97-2be2-41b6-9816-fb08757a4d1a

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-02-25

## Tags
attack.defense-evasion, attack.execution, attack.t1564, attack.t1059

## Description
Detects a potentially suspicious execution of a parent process located in the "\Users\Public" folder executing a child process containing references to shell or scripting binaries and commandlines.


## References
https://redcanary.com/blog/blackbyte-ransomware/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR (TgtProcCmdLine containsCIS "bitsadmin" OR TgtProcCmdLine containsCIS "certutil" OR TgtProcCmdLine containsCIS "cscript" OR TgtProcCmdLine containsCIS "mshta" OR TgtProcCmdLine containsCIS "powershell" OR TgtProcCmdLine containsCIS "regsvr32" OR TgtProcCmdLine containsCIS "rundll32" OR TgtProcCmdLine containsCIS "wscript")) AND SrcProcImagePath containsCIS ":\Users\Public\"))

```