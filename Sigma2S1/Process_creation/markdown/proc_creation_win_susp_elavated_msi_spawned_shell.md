# proc_creation_win_susp_elavated_msi_spawned_shell

## Title
Always Install Elevated MSI Spawned Cmd And Powershell

## ID
1e53dd56-8d83-4eb4-a43e-b790a05510aa

## Author
Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community

## Date
2020-10-13

## Tags
attack.privilege-escalation, attack.t1548.002

## Description
Detects Windows Installer service (msiexec.exe) spawning "cmd" or "powershell"

## References
https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-50-638.jpg

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND ((SrcProcImagePath containsCIS "\Windows\Installer\" AND SrcProcImagePath containsCIS "msi") AND SrcProcImagePath endswithCIS "tmp")))

```