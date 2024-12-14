# file_event_win_initial_access_dll_search_order_hijacking

## Title
Potential Initial Access via DLL Search Order Hijacking

## ID
dbbd9f66-2ed3-4ca2-98a4-6ea985dd1a1c

## Author
Tim Rauch (rule), Elastic (idea)

## Date
2022-10-21

## Tags
attack.t1566, attack.t1566.001, attack.initial-access, attack.t1574, attack.t1574.001, attack.defense-evasion

## Description
Detects attempts to create a DLL file to a known desktop application dependencies folder such as Slack, Teams or OneDrive and by an unusual process. This may indicate an attempt to load a malicious module via DLL search order hijacking.

## References
https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-5d46dd4ac6866b4337ec126be8cee0e115467b3e8703794ba6f6df6432c806bc
https://posts.specterops.io/automating-dll-hijack-discovery-81c4295904b0

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (((SrcProcImagePath endswithCIS "\winword.exe" OR SrcProcImagePath endswithCIS "\excel.exe" OR SrcProcImagePath endswithCIS "\powerpnt.exe" OR SrcProcImagePath endswithCIS "\MSACCESS.EXE" OR SrcProcImagePath endswithCIS "\MSPUB.EXE" OR SrcProcImagePath endswithCIS "\fltldr.exe" OR SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\certutil.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\wscript.exe" OR SrcProcImagePath endswithCIS "\curl.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe") AND (TgtFilePath containsCIS "\Microsoft\OneDrive\" OR TgtFilePath containsCIS "\Microsoft OneDrive\" OR TgtFilePath containsCIS "\Microsoft\Teams\" OR TgtFilePath containsCIS "\Local\slack\app-" OR TgtFilePath containsCIS "\Local\Programs\Microsoft VS Code\") AND (TgtFilePath containsCIS "\Users\" AND TgtFilePath containsCIS "\AppData\") AND TgtFilePath endswithCIS ".dll") AND (NOT (SrcProcImagePath endswithCIS "\cmd.exe" AND (TgtFilePath containsCIS "\Users\" AND TgtFilePath containsCIS "\AppData\" AND TgtFilePath containsCIS "\Microsoft\OneDrive\" AND TgtFilePath containsCIS "\api-ms-win-core-")))))

```