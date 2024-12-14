# proc_creation_win_susp_copy_system_dir_lolbin

## Title
LOL-Binary Copied From System Directory

## ID
f5d19838-41b5-476c-98d8-ba8af4929ee2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-29

## Tags
attack.defense-evasion, attack.t1036.003

## Description
Detects a suspicious copy operation that tries to copy a known LOLBIN from system (System32, SysWOW64, WinSxS) directories to another on disk in order to bypass detections based on locations.


## References
https://www.hybrid-analysis.com/sample/8da5b75b6380a41eee3a399c43dfe0d99eeefaa1fd21027a07b1ecaa4cd96fdd?environmentId=120
https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "copy " AND TgtProcImagePath endswithCIS "\cmd.exe") OR (TgtProcImagePath endswithCIS "\robocopy.exe" OR TgtProcImagePath endswithCIS "\xcopy.exe") OR ((TgtProcCmdLine containsCIS "copy-item" OR TgtProcCmdLine containsCIS " copy " OR TgtProcCmdLine containsCIS "cpi " OR TgtProcCmdLine containsCIS " cp ") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe"))) AND ((TgtProcCmdLine containsCIS "\bitsadmin.exe" OR TgtProcCmdLine containsCIS "\calc.exe" OR TgtProcCmdLine containsCIS "\certutil.exe" OR TgtProcCmdLine containsCIS "\cmdl32.exe" OR TgtProcCmdLine containsCIS "\cscript.exe" OR TgtProcCmdLine containsCIS "\mshta.exe" OR TgtProcCmdLine containsCIS "\rundll32.exe" OR TgtProcCmdLine containsCIS "\wscript.exe") AND (TgtProcCmdLine containsCIS "\System32" OR TgtProcCmdLine containsCIS "\SysWOW64" OR TgtProcCmdLine containsCIS "\WinSxS"))))

```