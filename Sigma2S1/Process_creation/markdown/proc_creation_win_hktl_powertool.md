# proc_creation_win_hktl_powertool

## Title
HackTool - PowerTool Execution

## ID
a34f79a3-8e5f-4cc3-b765-de00695452c2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-11-29

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects the execution of the tool PowerTool which has the ability to kill a process, delete its process file, unload drivers, and delete the driver files

## References
https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/
https://www.trendmicro.com/en_us/research/22/i/play-ransomware-s-attack-playbook-unmasks-it-as-another-hive-aff.html
https://twitter.com/gbti_sa/status/1249653895900602375?lang=en
https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\PowerTool.exe" OR TgtProcImagePath endswithCIS "\PowerTool64.exe"))

```