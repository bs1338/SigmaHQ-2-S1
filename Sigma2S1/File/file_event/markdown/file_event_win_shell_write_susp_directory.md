# file_event_win_shell_write_susp_directory

## Title
Windows Shell/Scripting Application File Write to Suspicious Folder

## ID
1277f594-a7d1-4f28-a2d3-73af5cbeab43

## Author
Florian Roth (Nextron Systems)

## Date
2021-11-20

## Tags
attack.execution, attack.t1059

## Description
Detects Windows shells and scripting applications that write files to suspicious folders

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (((SrcProcImagePath endswithCIS "\bash.exe" OR SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\msbuild.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\sh.exe" OR SrcProcImagePath endswithCIS "\wscript.exe") AND (TgtFilePath startswithCIS "C:\PerfLogs\" OR TgtFilePath startswithCIS "C:\Users\Public\")) OR ((SrcProcImagePath endswithCIS "\certutil.exe" OR SrcProcImagePath endswithCIS "\forfiles.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\schtasks.exe" OR SrcProcImagePath endswithCIS "\scriptrunner.exe" OR SrcProcImagePath endswithCIS "\wmic.exe") AND (TgtFilePath containsCIS "C:\PerfLogs\" OR TgtFilePath containsCIS "C:\Users\Public\" OR TgtFilePath containsCIS "C:\Windows\Temp\"))))

```