# proc_creation_win_pua_netscan

## Title
PUA - SoftPerfect Netscan Execution

## ID
ca387a8e-1c84-4da3-9993-028b45342d30

## Author
@d4ns4n_ (Wuerth-Phoenix)

## Date
2024-04-25

## Tags
attack.discovery, attack.t1046

## Description
Detects usage of SoftPerfect's "netscan.exe". An application for scanning networks.
It is actively used in-the-wild by threat actors to inspect and understand the network architecture of a victim.


## References
https://www.protect.airbus.com/blog/uncovering-cyber-intruders-netscan/
https://secjoes-reports.s3.eu-central-1.amazonaws.com/Sockbot%2Bin%2BGoLand.pdf
https://www.sentinelone.com/labs/black-basta-ransomware-attacks-deploy-custom-edr-evasion-tools-tied-to-fin7-threat-actor/
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/yanluowang-ransomware-attacks-continue
https://research.nccgroup.com/2022/07/13/climbing-mount-everest-black-byte-bytes-back/
https://www.bleepingcomputer.com/news/security/microsoft-exchange-servers-hacked-to-deploy-hive-ransomware/
https://www.softperfect.com/products/networkscanner/

## False Positives
Legitimate administrator activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\netscan.exe" OR TgtProcDisplayName = "Network Scanner" OR TgtProcDisplayName = "Application for scanning networks"))

```