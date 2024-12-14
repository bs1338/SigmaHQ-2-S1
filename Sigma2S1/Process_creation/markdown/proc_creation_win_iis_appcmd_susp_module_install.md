# proc_creation_win_iis_appcmd_susp_module_install

## Title
IIS Native-Code Module Command Line Installation

## ID
9465ddf4-f9e4-4ebd-8d98-702df3a93239

## Author
Florian Roth (Nextron Systems)

## Date
2019-12-11

## Tags
attack.persistence, attack.t1505.003

## Description
Detects suspicious IIS native-code module installations via command line

## References
https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
https://www.microsoft.com/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/

## False Positives
Unknown as it may vary from organisation to organisation how admins use to install IIS modules

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcCmdLine containsCIS "install" AND TgtProcCmdLine containsCIS "module") AND (TgtProcCmdLine containsCIS "-name:" OR TgtProcCmdLine containsCIS "/name:" OR TgtProcCmdLine containsCIS "â€“name:" OR TgtProcCmdLine containsCIS "â€”name:" OR TgtProcCmdLine containsCIS "â€•name:")) AND TgtProcImagePath endswithCIS "\appcmd.exe") AND (NOT SrcProcImagePath = "C:\Windows\System32\inetsrv\iissetup.exe")))

```