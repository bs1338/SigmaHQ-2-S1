# proc_creation_win_regsvr32_susp_child_process

## Title
Potentially Suspicious Child Process Of Regsvr32

## ID
6f0947a4-1c5e-4e0d-8ac7-53159b8f23ca

## Author
elhoim, Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-05-05

## Tags
attack.defense-evasion, attack.t1218.010

## Description
Detects potentially suspicious child processes of "regsvr32.exe".

## References
https://redcanary.com/blog/intelligence-insights-april-2022/
https://www.echotrail.io/insights/search/regsvr32.exe
https://www.ired.team/offensive-security/code-execution/t1117-regsvr32-aka-squiblydoo

## False Positives
Unlikely, but can rarely occur. Apply additional filters accordingly.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\calc.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\explorer.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe" OR TgtProcImagePath endswithCIS "\nltest.exe" OR TgtProcImagePath endswithCIS "\notepad.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\reg.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\werfault.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath endswithCIS "\regsvr32.exe") AND (NOT (TgtProcCmdLine containsCIS " -u -p " AND TgtProcImagePath endswithCIS "\werfault.exe"))))

```