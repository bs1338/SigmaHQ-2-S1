# proc_creation_win_powershell_script_engine_parent

## Title
Suspicious PowerShell Invocation From Script Engines

## ID
95eadcb2-92e4-4ed1-9031-92547773a6db

## Author
Florian Roth (Nextron Systems)

## Date
2019-01-16

## Tags
attack.execution, attack.t1059.001

## Description
Detects suspicious powershell invocations from interpreters or unusual programs

## References
https://www.securitynewspaper.com/2017/03/20/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/

## False Positives
Microsoft Operations Manager (MOM)
Other scripts

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (SrcProcImagePath endswithCIS "\wscript.exe" OR SrcProcImagePath endswithCIS "\cscript.exe")) AND (NOT TgtProcImagePath containsCIS "\Health Service State\")))

```