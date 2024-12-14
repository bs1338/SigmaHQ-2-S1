# proc_creation_win_susp_abusing_debug_privilege

## Title
Abused Debug Privilege by Arbitrary Parent Processes

## ID
d522eca2-2973-4391-a3e0-ef0374321dae

## Author
Semanur Guneysu @semanurtg, oscd.community

## Date
2020-10-28

## Tags
attack.privilege-escalation, attack.t1548

## Description
Detection of unusual child processes by different system processes

## References
https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-74-638.jpg

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\cmd.exe") AND ((SrcProcImagePath endswithCIS "\winlogon.exe" OR SrcProcImagePath endswithCIS "\services.exe" OR SrcProcImagePath endswithCIS "\lsass.exe" OR SrcProcImagePath endswithCIS "\csrss.exe" OR SrcProcImagePath endswithCIS "\smss.exe" OR SrcProcImagePath endswithCIS "\wininit.exe" OR SrcProcImagePath endswithCIS "\spoolsv.exe" OR SrcProcImagePath endswithCIS "\searchindexer.exe") AND (TgtProcUser containsCIS "AUTHORI" OR TgtProcUser containsCIS "AUTORI"))) AND (NOT (TgtProcCmdLine containsCIS " route " AND TgtProcCmdLine containsCIS " ADD "))))

```