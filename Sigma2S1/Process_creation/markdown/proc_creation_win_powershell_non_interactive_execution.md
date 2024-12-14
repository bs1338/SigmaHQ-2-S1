# proc_creation_win_powershell_non_interactive_execution

## Title
Non Interactive PowerShell Process Spawned

## ID
f4bbd493-b796-416e-bbf2-121235348529

## Author
Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements)

## Date
2019-09-12

## Tags
attack.execution, attack.t1059.001

## Description
Detects non-interactive PowerShell activity by looking at the "powershell" process with a non-user GUI process such as "explorer.exe" as a parent.

## References
https://web.archive.org/web/20200925032237/https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190410151110.html

## False Positives
Likely. Many admin scripts and tools leverage PowerShell in their BAT or VB scripts which may trigger this rule often. It is best to add additional filters or use this to hunt for anomalies

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (NOT ((SrcProcImagePath endswithCIS ":\Windows\explorer.exe" OR SrcProcImagePath endswithCIS ":\Windows\System32\CompatTelRunner.exe" OR SrcProcImagePath endswithCIS ":\Windows\SysWOW64\explorer.exe") OR SrcProcImagePath = ":\$WINDOWS.~BT\Sources\SetupHost.exe")) AND (NOT ((SrcProcImagePath containsCIS ":\Program Files\WindowsApps\Microsoft.WindowsTerminal_" AND SrcProcImagePath endswithCIS "\WindowsTerminal.exe") OR (SrcProcCmdLine containsCIS " --ms-enable-electron-run-as-node " AND SrcProcImagePath endswithCIS "\AppData\Local\Programs\Microsoft VS Code\Code.exe")))))

```