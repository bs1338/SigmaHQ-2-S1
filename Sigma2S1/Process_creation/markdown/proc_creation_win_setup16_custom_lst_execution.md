# proc_creation_win_setup16_custom_lst_execution

## Title
Setup16.EXE Execution With Custom .Lst File

## ID
99c8be4f-3087-4f9f-9c24-8c7e257b442e

## Author
frack113

## Date
2024-12-01

## Tags
attack.defense-evasion, attack.t1574.005

## Description
Detects the execution of "Setup16.EXE" and old installation utility with a custom ".lst" file.
These ".lst" file can contain references to external program that "Setup16.EXE" will execute.
Attackers and adversaries might leverage this as a living of the land utility.


## References
https://www.hexacorn.com/blog/2024/10/12/the-sweet16-the-oldbin-lolbin-called-setup16-exe/

## False Positives
On modern Windows system, the "Setup16" utility is practically never used, hence false positive should be very rare.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcCmdLine containsCIS " -m " AND SrcProcImagePath = "C:\Windows\SysWOW64\setup16.exe") AND (NOT TgtProcImagePath startswithCIS "C:\~MSSETUP.T\")))

```