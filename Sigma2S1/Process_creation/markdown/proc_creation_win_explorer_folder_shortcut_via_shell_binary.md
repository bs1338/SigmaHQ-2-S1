# proc_creation_win_explorer_folder_shortcut_via_shell_binary

## Title
File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell

## ID
c3d76afc-93df-461e-8e67-9b2bad3f2ac4

## Author
@Kostastsale

## Date
2022-12-22

## Tags
attack.discovery, attack.t1135

## Description
Detects the initial execution of "cmd.exe" which spawns "explorer.exe" with the appropriate command line arguments for opening the "My Computer" folder.


## References
https://ss64.com/nt/shell.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "shell:mycomputerfolder" AND TgtProcImagePath endswithCIS "\explorer.exe" AND (SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe")))

```