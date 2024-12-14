# file_event_win_create_non_existent_dlls

## Title
Creation Of Non-Existent System DLL

## ID
df6ecb8b-7822-4f4b-b412-08f524b4576c

## Author
Nasreddine Bencherchali (Nextron Systems), fornotes

## Date
2022-12-01

## Tags
attack.defense-evasion, attack.persistence, attack.privilege-escalation, attack.t1574.001, attack.t1574.002

## Description
Detects the creation of system DLLs that are usually not present on the system (or at least not in system directories).
Usually this technique is used to achieve DLL hijacking.


## References
https://decoded.avast.io/martinchlumecky/png-steganography/
https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992
https://clement.notin.org/blog/2020/09/12/CVE-2020-7315-McAfee-Agent-DLL-injection/
https://github.com/Wh04m1001/SysmonEoP
https://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/
https://github.com/blackarrowsec/redteam-research/tree/26e6fc0c0d30d364758fa11c2922064a9a7fd309/LPE%20via%20StorSvc

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ":\Windows\System32\TSMSISrv.dll" OR TgtFilePath endswithCIS ":\Windows\System32\TSVIPSrv.dll" OR TgtFilePath endswithCIS ":\Windows\System32\wbem\wbemcomn.dll" OR TgtFilePath endswithCIS ":\Windows\System32\WLBSCTRL.dll" OR TgtFilePath endswithCIS ":\Windows\System32\wow64log.dll" OR TgtFilePath endswithCIS ":\Windows\System32\WptsExtensions.dll" OR TgtFilePath endswithCIS "\SprintCSP.dll"))

```