# proc_creation_win_susp_shell_spawn_susp_program

## Title
Windows Shell/Scripting Processes Spawning Suspicious Programs

## ID
3a6586ad-127a-4d3b-a677-1e6eacdf8fde

## Author
Florian Roth (Nextron Systems), Tim Shelton

## Date
2018-04-06

## Tags
attack.execution, attack.defense-evasion, attack.t1059.005, attack.t1059.001, attack.t1218

## Description
Detects suspicious child processes of a Windows shell and scripting processes such as wscript, rundll32, powershell, mshta...etc.

## References
https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html

## False Positives
Administrative scripts
Microsoft SCCM

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\nslookup.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\mshta.exe") AND (SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\wscript.exe" OR SrcProcImagePath endswithCIS "\wmiprvse.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe")) AND (NOT ((SrcProcCmdLine containsCIS "\Program Files\Amazon\WorkSpacesConfig\Scripts\setup-scheduledtask.ps1" OR SrcProcCmdLine containsCIS "\Program Files\Amazon\WorkSpacesConfig\Scripts\set-selfhealing.ps1" OR SrcProcCmdLine containsCIS "\Program Files\Amazon\WorkSpacesConfig\Scripts\check-workspacehealth.ps1" OR SrcProcCmdLine containsCIS "\nessus_") OR TgtProcImagePath containsCIS "\ccmcache\" OR TgtProcCmdLine containsCIS "\nessus_" OR ((TgtProcCmdLine containsCIS "C:\MEM_Configmgr_" AND TgtProcCmdLine containsCIS "\SMSSETUP\BIN\" AND TgtProcCmdLine containsCIS "\autorun.hta" AND TgtProcCmdLine containsCIS "{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}") AND TgtProcImagePath endswithCIS "\mshta.exe" AND (SrcProcCmdLine containsCIS "C:\MEM_Configmgr_" AND SrcProcCmdLine containsCIS "\splash.hta" AND SrcProcCmdLine containsCIS "{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}") AND SrcProcImagePath endswithCIS "\mshta.exe")))))

```