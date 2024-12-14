# proc_creation_win_renamed_binary_highly_relevant

## Title
Potential Defense Evasion Via Rename Of Highly Relevant Binaries

## ID
0ba1da6d-b6ce-4366-828c-18826c9de23e

## Author
Matthew Green - @mgreen27, Florian Roth (Nextron Systems), frack113

## Date
2019-06-15

## Tags
attack.defense-evasion, attack.t1036.003, car.2013-05-009

## Description
Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.

## References
https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html
https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html
https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/megacortex-ransomware-spotted-attacking-enterprise-networks
https://twitter.com/christophetd/status/1164506034720952320
https://threatresearch.ext.hp.com/svcready-a-new-loader-reveals-itself/

## False Positives
Custom applications use renamed binaries adding slight change to binary name. Typically this is easy to spot and add to whitelist
PsExec installed via Windows Store doesn't contain original filename field (False negative)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcDisplayName = "Execute processes remotely" OR TgtProcDisplayName = "Sysinternals PsExec" OR (TgtProcDisplayName startswithCIS "Windows PowerShell" OR TgtProcDisplayName startswithCIS "pwsh")) AND (NOT (TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cmstp.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\ie4uinit.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\msxsl.exe" OR TgtProcImagePath endswithCIS "\powershell_ise.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\psexec.exe" OR TgtProcImagePath endswithCIS "\psexec64.exe" OR TgtProcImagePath endswithCIS "\PSEXESVC.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\reg.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wermgr.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\wscript.exe"))))

```