# proc_creation_win_rundll32_susp_shellexec_ordinal_execution

## Title
Suspicious ShellExec_RunDLL Call Via Ordinal

## ID
8823e85d-31d8-473e-b7f4-92da070f0fc6

## Author
Swachchhanda Shrawan Poudel

## Date
2024-12-01

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects suspicious call to the "ShellExec_RunDLL" exported function of SHELL32.DLL through the ordinal number to launch other commands.
Adversary might only use the ordinal number in order to bypass existing detection that alert on usage of ShellExec_RunDLL on CommandLine.


## References
https://redcanary.com/blog/raspberry-robin/
https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/
https://github.com/SigmaHQ/sigma/issues/1009
https://strontic.github.io/xcyclopedia/library/shell32.dll-65DA072F25DE83D9F83653E3FEA3644D.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcCmdLine containsCIS "SHELL32.DLL" AND (SrcProcCmdLine containsCIS "#568" OR SrcProcCmdLine containsCIS "#570" OR SrcProcCmdLine containsCIS "#572" OR SrcProcCmdLine containsCIS "#576")) AND ((TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\curl.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\msxsl.exe" OR TgtProcImagePath endswithCIS "\odbcconf.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR ((SrcProcCmdLine containsCIS "comspec" OR SrcProcCmdLine containsCIS "iex" OR SrcProcCmdLine containsCIS "Invoke-" OR SrcProcCmdLine containsCIS "msiexec" OR SrcProcCmdLine containsCIS "odbcconf" OR SrcProcCmdLine containsCIS "regsvr32") OR (SrcProcCmdLine containsCIS "\Desktop\" OR SrcProcCmdLine containsCIS "\ProgramData\" OR SrcProcCmdLine containsCIS "\Temp\" OR SrcProcCmdLine containsCIS "\Users\Public\")))))

```