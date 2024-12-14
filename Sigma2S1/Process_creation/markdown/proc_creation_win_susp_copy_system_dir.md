# proc_creation_win_susp_copy_system_dir

## Title
Suspicious Copy From or To System Directory

## ID
fff9d2b7-e11c-4a69-93d3-40ef66189767

## Author
Florian Roth (Nextron Systems), Markus Neis, Tim Shelton (HAWK.IO), Nasreddine Bencherchali (Nextron Systems)

## Date
2020-07-03

## Tags
attack.defense-evasion, attack.t1036.003

## Description
Detects a suspicious copy operation that tries to copy a program from system (System32, SysWOW64, WinSxS) directories to another on disk.
Often used to move LOLBINs such as 'certutil' or 'desktopimgdownldr' to a different location with a different name in order to bypass detections based on locations.


## References
https://www.hybrid-analysis.com/sample/8da5b75b6380a41eee3a399c43dfe0d99eeefaa1fd21027a07b1ecaa4cd96fdd?environmentId=120
https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/

## False Positives
Depend on scripts and administrative tools used in the monitored environment (For example an admin scripts like https://www.itexperience.net/sccm-batch-files-and-32-bits-processes-on-64-bits-os/)
When cmd.exe and xcopy.exe are called directly
When the command contains the keywords but not in the correct order

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "copy " AND TgtProcImagePath endswithCIS "\cmd.exe") OR (TgtProcImagePath endswithCIS "\robocopy.exe" OR TgtProcImagePath endswithCIS "\xcopy.exe") OR ((TgtProcCmdLine containsCIS "copy-item" OR TgtProcCmdLine containsCIS " copy " OR TgtProcCmdLine containsCIS "cpi " OR TgtProcCmdLine containsCIS " cp ") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe"))) AND (TgtProcCmdLine containsCIS "\System32" OR TgtProcCmdLine containsCIS "\SysWOW64" OR TgtProcCmdLine containsCIS "\WinSxS")))

```