# proc_creation_win_susp_script_exec_from_env_folder

## Title
Script Interpreter Execution From Suspicious Folder

## ID
1228c958-e64e-4e71-92ad-7d429f4138ba

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-02-08

## Tags
attack.execution, attack.t1059

## Description
Detects a suspicious script execution in temporary folders or folders accessible by environment variables

## References
https://www.virustotal.com/gui/file/91ba814a86ddedc7a9d546e26f912c541205b47a853d227756ab1334ade92c3f
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-russia-ukraine-military
https://learn.microsoft.com/en-us/windows/win32/shell/csidl

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -ep bypass " OR TgtProcCmdLine containsCIS " -ExecutionPolicy bypass " OR TgtProcCmdLine containsCIS " -w hidden " OR TgtProcCmdLine containsCIS "/e:javascript " OR TgtProcCmdLine containsCIS "/e:Jscript " OR TgtProcCmdLine containsCIS "/e:vbscript ") OR (TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\wscript.exe")) AND ((TgtProcCmdLine containsCIS ":\Perflogs\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp" OR TgtProcCmdLine containsCIS "\AppData\Roaming\Temp" OR TgtProcCmdLine containsCIS "\Temporary Internet" OR TgtProcCmdLine containsCIS "\Windows\Temp") OR ((TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Favorites\") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Favourites\") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Contacts\")))))

```