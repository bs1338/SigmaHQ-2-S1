# proc_creation_win_hktl_empire_powershell_uac_bypass

## Title
HackTool - Empire PowerShell UAC Bypass

## ID
3268b746-88d8-4cd3-bffc-30077d02c787

## Author
Ecco

## Date
2019-08-30

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002, car.2019-04-001

## Description
Detects some Empire PowerShell UAC bypass methods

## References
https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\Microsoft\Windows Update).Update)" OR TgtProcCmdLine containsCIS " -NoP -NonI -c $x=$((gp HKCU:Software\Microsoft\Windows Update).Update);"))

```