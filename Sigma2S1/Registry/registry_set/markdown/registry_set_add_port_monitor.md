# registry_set_add_port_monitor

## Title
Add Port Monitor Persistence in Registry

## ID
944e8941-f6f6-4ee8-ac05-1c224e923c0e

## Author
frack113

## Date
2021-12-30

## Tags
attack.persistence, attack.t1547.010

## Description
Adversaries may use port monitors to run an attacker supplied DLL during system boot for persistence or privilege escalation.
A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.010/T1547.010.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue endswithCIS ".dll" AND RegistryKeyPath containsCIS "\Control\Print\Monitors\") AND (NOT ((RegistryValue = "cpwmon64_v40.dll" AND SrcProcImagePath = "C:\Windows\System32\spoolsv.exe" AND RegistryKeyPath containsCIS "\Control\Print\Monitors\CutePDF Writer Monitor v4.0\Driver" AND (User containsCIS "AUTHORI" OR User containsCIS "AUTORI")) OR RegistryKeyPath containsCIS "\Control\Print\Monitors\MONVNC\Driver" OR (RegistryKeyPath containsCIS "Control\Print\Environments\" AND RegistryKeyPath containsCIS "\Drivers\" AND RegistryKeyPath containsCIS "\VNC Printer")))))

```