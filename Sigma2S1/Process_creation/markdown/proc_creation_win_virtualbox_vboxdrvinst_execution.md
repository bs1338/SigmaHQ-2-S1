# proc_creation_win_virtualbox_vboxdrvinst_execution

## Title
Suspicious VBoxDrvInst.exe Parameters

## ID
b7b19cb6-9b32-4fc4-a108-73f19acfe262

## Author
Konstantin Grishchenko, oscd.community

## Date
2020-10-06

## Tags
attack.defense-evasion, attack.t1112

## Description
Detect VBoxDrvInst.exe run with parameters allowing processing INF file.
 This allows to create values in the registry and install drivers.
For example one could use this technique to obtain persistence via modifying one of Run or RunOnce registry keys


## References
https://github.com/LOLBAS-Project/LOLBAS/blob/4db780e0f0b2e2bb8cb1fa13e09196da9b9f1834/yml/LOLUtilz/OtherBinaries/VBoxDrvInst.yml
https://twitter.com/pabraeken/status/993497996179492864

## False Positives
Legitimate use of VBoxDrvInst.exe utility by VirtualBox Guest Additions installation process

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "driver" AND TgtProcCmdLine containsCIS "executeinf") AND TgtProcImagePath endswithCIS "\VBoxDrvInst.exe"))

```