# proc_creation_win_wmiprvse_susp_child_processes

## Title
Suspicious WmiPrvSE Child Process

## ID
8a582fe2-0882-4b89-a82a-da6b2dc32937

## Author
Vadim Khrykov (ThreatIntel), Cyb3rEng, Florian Roth (Nextron Systems)

## Date
2021-08-23

## Tags
attack.execution, attack.defense-evasion, attack.t1047, attack.t1204.002, attack.t1218.010

## Description
Detects suspicious and uncommon child processes of WmiPrvSE

## References
https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/02bcbfc2bfb8b4da601bb30de0344ae453aa1afe/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml
https://blog.osarmor.com/319/onenote-attachment-delivers-asyncrat-malware/
https://twitter.com/ForensicITGuy/status/1334734244120309760

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\wbem\WmiPrvSE.exe" AND ((TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\verclsid.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR ((TgtProcCmdLine containsCIS "cscript" OR TgtProcCmdLine containsCIS "mshta" OR TgtProcCmdLine containsCIS "powershell" OR TgtProcCmdLine containsCIS "pwsh" OR TgtProcCmdLine containsCIS "regsvr32" OR TgtProcCmdLine containsCIS "rundll32" OR TgtProcCmdLine containsCIS "wscript") AND TgtProcImagePath endswithCIS "\cmd.exe")) AND (NOT ((TgtProcCmdLine containsCIS "/i " AND TgtProcImagePath endswithCIS "\msiexec.exe") OR TgtProcImagePath endswithCIS "\WerFault.exe" OR TgtProcImagePath endswithCIS "\WmiPrvSE.exe"))))

```