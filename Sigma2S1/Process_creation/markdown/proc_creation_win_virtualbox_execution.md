# proc_creation_win_virtualbox_execution

## Title
Detect Virtualbox Driver Installation OR Starting Of VMs

## ID
bab049ca-7471-4828-9024-38279a4c04da

## Author
Janantha Marasinghe

## Date
2020-09-26

## Tags
attack.defense-evasion, attack.t1564.006, attack.t1564

## Description
Adversaries can carry out malicious operations using a virtual instance to avoid detection. This rule is built to detect the registration of the Virtualbox driver or start of a Virtualbox VM.

## References
https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
https://threatpost.com/maze-ransomware-ragnar-locker-virtual-machine/159350/

## False Positives
This may have false positives on hosts where Virtualbox is legitimately being used for operations

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "VBoxRT.dll,RTR3Init" OR TgtProcCmdLine containsCIS "VBoxC.dll" OR TgtProcCmdLine containsCIS "VBoxDrv.sys") OR (TgtProcCmdLine containsCIS "startvm" OR TgtProcCmdLine containsCIS "controlvm")))

```