# proc_creation_win_java_keytool_susp_child_process

## Title
Suspicious Shells Spawn by Java Utility Keytool

## ID
90fb5e62-ca1f-4e22-b42e-cc521874c938

## Author
Andreas Hunkeler (@Karneades)

## Date
2021-12-22

## Tags
attack.initial-access, attack.persistence, attack.privilege-escalation

## Description
Detects suspicious shell spawn from Java utility keytool process (e.g. adselfservice plus exploitation)

## References
https://redcanary.com/blog/intelligence-insights-december-2021
https://www.synacktiv.com/en/publications/how-to-exploit-cve-2021-40539-on-manageengine-adselfservice-plus.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\whoami.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\scrcons.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\hh.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\forfiles.exe" OR TgtProcImagePath endswithCIS "\scriptrunner.exe" OR TgtProcImagePath endswithCIS "\mftrace.exe" OR TgtProcImagePath endswithCIS "\AppVLP.exe" OR TgtProcImagePath endswithCIS "\systeminfo.exe" OR TgtProcImagePath endswithCIS "\reg.exe" OR TgtProcImagePath endswithCIS "\query.exe") AND SrcProcImagePath endswithCIS "\keytool.exe"))

```