# proc_creation_win_spoolsv_susp_child_processes

## Title
Suspicious Spool Service Child Process

## ID
dcdbc940-0bff-46b2-95f3-2d73f848e33b

## Author
Justin C. (@endisphotic), @dreadphones (detection), Thomas Patzke (Sigma rule)

## Date
2021-07-11

## Tags
attack.execution, attack.t1203, attack.privilege-escalation, attack.t1068

## Description
Detects suspicious print spool service (spoolsv.exe) child processes.

## References
https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/efa17a600b43c897b4b7463cc8541daa1987eeb4/Exploits/Print%20Spooler%20RCE/Suspicious%20Spoolsv%20Child%20Process.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcIntegrityLevel In ("System","S-1-16-16384")) AND SrcProcImagePath endswithCIS "\spoolsv.exe") AND ((TgtProcImagePath endswithCIS "\gpupdate.exe" OR TgtProcImagePath endswithCIS "\whoami.exe" OR TgtProcImagePath endswithCIS "\nltest.exe" OR TgtProcImagePath endswithCIS "\taskkill.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\taskmgr.exe" OR TgtProcImagePath endswithCIS "\sc.exe" OR TgtProcImagePath endswithCIS "\findstr.exe" OR TgtProcImagePath endswithCIS "\curl.exe" OR TgtProcImagePath endswithCIS "\wget.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\accesschk.exe" OR TgtProcImagePath endswithCIS "\wevtutil.exe" OR TgtProcImagePath endswithCIS "\bcdedit.exe" OR TgtProcImagePath endswithCIS "\fsutil.exe" OR TgtProcImagePath endswithCIS "\cipher.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\write.exe" OR TgtProcImagePath endswithCIS "\wuauclt.exe" OR TgtProcImagePath endswithCIS "\systeminfo.exe" OR TgtProcImagePath endswithCIS "\reg.exe" OR TgtProcImagePath endswithCIS "\query.exe") OR ((TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe") AND (NOT TgtProcCmdLine containsCIS "start")) OR (TgtProcImagePath endswithCIS "\cmd.exe" AND (NOT (TgtProcCmdLine containsCIS ".spl" OR TgtProcCmdLine containsCIS "route add" OR TgtProcCmdLine containsCIS "program files"))) OR (TgtProcImagePath endswithCIS "\netsh.exe" AND (NOT (TgtProcCmdLine containsCIS "add portopening" OR TgtProcCmdLine containsCIS "rule name"))) OR ((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (NOT TgtProcCmdLine containsCIS ".spl")) OR (TgtProcCmdLine endswithCIS "rundll32.exe" AND TgtProcImagePath endswithCIS "\rundll32.exe"))))

```