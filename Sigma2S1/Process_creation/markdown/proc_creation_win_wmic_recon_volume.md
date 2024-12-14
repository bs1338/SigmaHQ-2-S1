# proc_creation_win_wmic_recon_volume

## Title
System Disk And Volume Reconnaissance Via Wmic.EXE

## ID
c79da740-5030-45ec-a2e0-479e824a562c

## Author
Stephen Lincoln `@slincoln-aiq`(AttackIQ)

## Date
2024-02-02

## Tags
attack.execution, attack.discovery, attack.t1047, attack.t1082

## Description
An adversary might use WMI to discover information about the system, such as the volume name, size,
free space, and other disk information. This can be done using the `wmic` command-line utility and has been
observed being used by threat actors such as Volt Typhoon.


## References
https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "volume" OR TgtProcCmdLine containsCIS "path win32_logicaldisk") AND TgtProcImagePath endswithCIS "\WMIC.exe"))

```