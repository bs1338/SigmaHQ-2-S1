# proc_creation_win_conhost_uncommon_parent

## Title
Conhost Spawned By Uncommon Parent Process

## ID
cbb9e3d1-2386-4e59-912e-62f1484f7a89

## Author
Tim Rauch, Elastic (idea)

## Date
2022-09-28

## Tags
attack.execution, attack.t1059

## Description
Detects when the Console Window Host (conhost.exe) process is spawned by an uncommon parent process, which could be indicative of potential code injection activity.

## References
https://www.elastic.co/guide/en/security/current/conhost-spawned-by-suspicious-parent-process.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\conhost.exe" AND (SrcProcImagePath endswithCIS "\explorer.exe" OR SrcProcImagePath endswithCIS "\lsass.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\services.exe" OR SrcProcImagePath endswithCIS "\smss.exe" OR SrcProcImagePath endswithCIS "\spoolsv.exe" OR SrcProcImagePath endswithCIS "\svchost.exe" OR SrcProcImagePath endswithCIS "\userinit.exe" OR SrcProcImagePath endswithCIS "\wininit.exe" OR SrcProcImagePath endswithCIS "\winlogon.exe")) AND (NOT (SrcProcCmdLine containsCIS "-k apphost -s AppHostSvc" OR SrcProcCmdLine containsCIS "-k imgsvc" OR SrcProcCmdLine containsCIS "-k localService -p -s RemoteRegistry" OR SrcProcCmdLine containsCIS "-k LocalSystemNetworkRestricted -p -s NgcSvc" OR SrcProcCmdLine containsCIS "-k NetSvcs -p -s NcaSvc" OR SrcProcCmdLine containsCIS "-k netsvcs -p -s NetSetupSvc" OR SrcProcCmdLine containsCIS "-k netsvcs -p -s wlidsvc" OR SrcProcCmdLine containsCIS "-k NetworkService -p -s DoSvc" OR SrcProcCmdLine containsCIS "-k wsappx -p -s AppXSvc" OR SrcProcCmdLine containsCIS "-k wsappx -p -s ClipSVC")) AND (NOT (SrcProcCmdLine containsCIS "C:\Program Files (x86)\Dropbox\Client\" OR SrcProcCmdLine containsCIS "C:\Program Files\Dropbox\Client\"))))

```