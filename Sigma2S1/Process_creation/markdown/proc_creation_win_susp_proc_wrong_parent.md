# proc_creation_win_susp_proc_wrong_parent

## Title
Windows Processes Suspicious Parent Directory

## ID
96036718-71cc-4027-a538-d1587e0006a7

## Author
vburov

## Date
2019-02-23

## Tags
attack.defense-evasion, attack.t1036.003, attack.t1036.005

## Description
Detect suspicious parent processes of well-known Windows processes

## References
https://web.archive.org/web/20180718061628/https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2
https://www.carbonblack.com/2014/06/10/screenshot-demo-hunt-evil-faster-than-ever-with-carbon-black/
https://www.13cubed.com/downloads/windows_process_genealogy_v2.pdf

## False Positives
Some security products seem to spawn these

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\svchost.exe" OR TgtProcImagePath endswithCIS "\taskhost.exe" OR TgtProcImagePath endswithCIS "\lsm.exe" OR TgtProcImagePath endswithCIS "\lsass.exe" OR TgtProcImagePath endswithCIS "\services.exe" OR TgtProcImagePath endswithCIS "\lsaiso.exe" OR TgtProcImagePath endswithCIS "\csrss.exe" OR TgtProcImagePath endswithCIS "\wininit.exe" OR TgtProcImagePath endswithCIS "\winlogon.exe") AND (NOT (((SrcProcImagePath containsCIS "\Windows Defender\" OR SrcProcImagePath containsCIS "\Microsoft Security Client\") AND SrcProcImagePath endswithCIS "\MsMpEng.exe") OR (SrcProcImagePath IS NOT EMPTY OR SrcProcImagePath = "-") OR ((SrcProcImagePath endswithCIS "\SavService.exe" OR SrcProcImagePath endswithCIS "\ngen.exe") OR (SrcProcImagePath containsCIS "\System32\" OR SrcProcImagePath containsCIS "\SysWOW64\"))))))

```