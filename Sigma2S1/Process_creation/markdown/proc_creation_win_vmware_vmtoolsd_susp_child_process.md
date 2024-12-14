# proc_creation_win_vmware_vmtoolsd_susp_child_process

## Title
VMToolsd Suspicious Child Process

## ID
5687f942-867b-4578-ade7-1e341c46e99a

## Author
bohops, Bhabesh Raj

## Date
2021-10-08

## Tags
attack.execution, attack.persistence, attack.t1059

## Description
Detects suspicious child process creations of VMware Tools process which may indicate persistence setup

## References
https://bohops.com/2021/10/08/analyzing-and-detecting-a-vmtools-persistence-technique/
https://user-images.githubusercontent.com/61026070/136518004-b68cce7d-f9b8-4e9a-9b7b-53b1568a9a94.png
https://github.com/vmware/open-vm-tools/blob/master/open-vm-tools/tools.conf

## False Positives
Legitimate use by VM administrator

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath endswithCIS "\vmtoolsd.exe") AND (NOT ((TgtProcCmdLine = "" AND TgtProcImagePath endswithCIS "\cmd.exe") OR (TgtProcCmdLine IS NOT EMPTY AND TgtProcImagePath endswithCIS "\cmd.exe") OR ((TgtProcCmdLine containsCIS "\VMware\VMware Tools\poweron-vm-default.bat" OR TgtProcCmdLine containsCIS "\VMware\VMware Tools\poweroff-vm-default.bat" OR TgtProcCmdLine containsCIS "\VMware\VMware Tools\resume-vm-default.bat" OR TgtProcCmdLine containsCIS "\VMware\VMware Tools\suspend-vm-default.bat") AND TgtProcImagePath endswithCIS "\cmd.exe")))))

```