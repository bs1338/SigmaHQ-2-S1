# proc_creation_win_susp_non_exe_image

## Title
Execution of Suspicious File Type Extension

## ID
c09dad97-1c78-4f71-b127-7edb2b8e491a

## Author
Max Altgelt (Nextron Systems)

## Date
2021-12-09

## Tags
attack.defense-evasion

## Description
Detects whether the image specified in a process creation event doesn't refer to an ".exe" (or other known executable extension) file. This can be caused by process ghosting or other unorthodox methods to start a process.
This rule might require some initial baselining to align with some third party tooling in the user environment.


## References
https://pentestlaboratories.com/2021/12/08/process-ghosting/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((NOT (TgtProcImagePath endswithCIS ".bin" OR TgtProcImagePath endswithCIS ".cgi" OR TgtProcImagePath endswithCIS ".com" OR TgtProcImagePath endswithCIS ".exe" OR TgtProcImagePath endswithCIS ".scr" OR TgtProcImagePath endswithCIS ".tmp")) AND (NOT (TgtProcImagePath containsCIS ":\$Extend\$Deleted\" OR TgtProcImagePath containsCIS ":\Windows\System32\DriverStore\FileRepository\" OR (TgtProcImagePath In Contains AnyCase ("-","")) OR (TgtProcImagePath In Contains AnyCase ("System","Registry","MemCompression","vmmem")) OR TgtProcImagePath containsCIS ":\Windows\Installer\MSI" OR (TgtProcImagePath containsCIS ":\Config.Msi\" AND (TgtProcImagePath endswithCIS ".rbf" OR TgtProcImagePath endswithCIS ".rbs")) OR TgtProcImagePath IS NOT EMPTY OR (SrcProcImagePath containsCIS ":\Windows\Temp\" OR TgtProcImagePath containsCIS ":\Windows\Temp\"))) AND (NOT (SrcProcImagePath containsCIS ":\ProgramData\Avira\" OR (TgtProcImagePath endswithCIS "com.docker.service" AND SrcProcImagePath = "C:\Windows\System32\services.exe") OR TgtProcImagePath containsCIS ":\Program Files\Mozilla Firefox\" OR TgtProcImagePath endswithCIS "\LZMA_EXE" OR (TgtProcImagePath endswithCIS ":\Program Files (x86)\MyQ\Server\pcltool.dll" OR TgtProcImagePath endswithCIS ":\Program Files\MyQ\Server\pcltool.dll") OR (TgtProcImagePath containsCIS "NVIDIA\NvBackend\" AND TgtProcImagePath endswithCIS ".dat") OR ((TgtProcImagePath containsCIS ":\Program Files (x86)\WINPAKPRO\" OR TgtProcImagePath containsCIS ":\Program Files\WINPAKPRO\") AND TgtProcImagePath endswithCIS ".ngn") OR (TgtProcImagePath containsCIS "\AppData\Local\Packages\" AND TgtProcImagePath containsCIS "\LocalState\rootfs\")))))

```