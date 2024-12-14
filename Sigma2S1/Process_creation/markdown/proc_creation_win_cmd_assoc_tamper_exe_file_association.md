# proc_creation_win_cmd_assoc_tamper_exe_file_association

## Title
Change Default File Association To Executable Via Assoc

## ID
ae6f14e6-14de-45b0-9f44-c0986f50dc89

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-28

## Tags
attack.persistence, attack.t1546.001

## Description
Detects when a program changes the default file association of any extension to an executable.
When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.


## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/assoc

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "assoc " AND TgtProcCmdLine containsCIS "exefile") AND TgtProcImagePath endswithCIS "\cmd.exe") AND (NOT TgtProcCmdLine containsCIS ".exe=exefile")))

```