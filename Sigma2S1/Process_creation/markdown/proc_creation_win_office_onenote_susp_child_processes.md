# proc_creation_win_office_onenote_susp_child_processes

## Title
Suspicious Microsoft OneNote Child Process

## ID
c27515df-97a9-4162-8a60-dc0eeb51b775

## Author
Tim Rauch (Nextron Systems), Nasreddine Bencherchali (Nextron Systems), Elastic (idea)

## Date
2022-10-21

## Tags
attack.t1566, attack.t1566.001, attack.initial-access

## Description
Detects suspicious child processes of the Microsoft OneNote application. This may indicate an attempt to execute malicious embedded objects from a .one file.

## References
https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-e34e43eb5666427602ddf488b2bf3b545bd9aae81af3e6f6c7949f9652abdf18
https://micahbabinski.medium.com/detecting-onenote-one-malware-delivery-407e9321ecf0

## False Positives
File located in the AppData folder with trusted signature

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\onenote.exe" AND (((TgtProcCmdLine containsCIS ".hta" OR TgtProcCmdLine containsCIS ".vb" OR TgtProcCmdLine containsCIS ".wsh" OR TgtProcCmdLine containsCIS ".js" OR TgtProcCmdLine containsCIS ".ps" OR TgtProcCmdLine containsCIS ".scr" OR TgtProcCmdLine containsCIS ".pif" OR TgtProcCmdLine containsCIS ".bat" OR TgtProcCmdLine containsCIS ".cmd") AND TgtProcImagePath endswithCIS "\explorer.exe") OR (TgtProcImagePath endswithCIS "\AppVLP.exe" OR TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\certoc.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cmstp.exe" OR TgtProcImagePath endswithCIS "\control.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\curl.exe" OR TgtProcImagePath endswithCIS "\forfiles.exe" OR TgtProcImagePath endswithCIS "\hh.exe" OR TgtProcImagePath endswithCIS "\ieexec.exe" OR TgtProcImagePath endswithCIS "\installutil.exe" OR TgtProcImagePath endswithCIS "\javaw.exe" OR TgtProcImagePath endswithCIS "\mftrace.exe" OR TgtProcImagePath endswithCIS "\Microsoft.Workflow.Compiler.exe" OR TgtProcImagePath endswithCIS "\msbuild.exe" OR TgtProcImagePath endswithCIS "\msdt.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\msidb.exe" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\msxsl.exe" OR TgtProcImagePath endswithCIS "\odbcconf.exe" OR TgtProcImagePath endswithCIS "\pcalua.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regasm.exe" OR TgtProcImagePath endswithCIS "\regsvcs.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\scrcons.exe" OR TgtProcImagePath endswithCIS "\scriptrunner.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\svchost.exe" OR TgtProcImagePath endswithCIS "\verclsid.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\workfolders.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR (TgtProcImagePath containsCIS "\AppData\" OR TgtProcImagePath containsCIS "\Users\Public\" OR TgtProcImagePath containsCIS "\ProgramData\" OR TgtProcImagePath containsCIS "\Windows\Tasks\" OR TgtProcImagePath containsCIS "\Windows\Temp\" OR TgtProcImagePath containsCIS "\Windows\System32\Tasks\")) AND (NOT ((TgtProcCmdLine endswithCIS "-Embedding" AND TgtProcImagePath containsCIS "\AppData\Local\Microsoft\OneDrive\" AND TgtProcImagePath endswithCIS "\FileCoAuth.exe") OR (TgtProcCmdLine endswithCIS "-Embedding" AND TgtProcImagePath endswithCIS "\AppData\Local\Microsoft\Teams\current\Teams.exe")))))

```