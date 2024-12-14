# file_event_win_hktl_powerup_dllhijacking

## Title
HackTool - Powerup Write Hijack DLL

## ID
602a1f13-c640-4d73-b053-be9a2fa58b96

## Author
Subhash Popuri (@pbssubhash)

## Date
2021-08-21

## Tags
attack.persistence, attack.privilege-escalation, attack.defense-evasion, attack.t1574.001

## Description
Powerup tool's Write Hijack DLL exploits DLL hijacking for privilege escalation.
In it's default mode, it builds a self deleting .bat file which executes malicious command.
The detection rule relies on creation of the malicious bat file (debug.bat by default).


## References
https://powersploit.readthedocs.io/en/latest/Privesc/Write-HijackDll/

## False Positives
Any powershell script that creates bat files

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe") AND TgtFilePath endswithCIS ".bat"))

```