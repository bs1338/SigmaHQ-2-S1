# proc_creation_win_hktl_crackmapexec_powershell_obfuscation

## Title
HackTool - CrackMapExec PowerShell Obfuscation

## ID
6f8b3439-a203-45dc-a88b-abf57ea15ccf

## Author
Thomas Patzke

## Date
2020-05-22

## Tags
attack.execution, attack.t1059.001, attack.defense-evasion, attack.t1027.005

## Description
The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.

## References
https://github.com/byt3bl33d3r/CrackMapExec
https://github.com/byt3bl33d3r/CrackMapExec/blob/0a49f75347b625e81ee6aa8c33d3970b5515ea9e/cme/helpers/powershell.py#L242

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine = "*join*split*" OR TgtProcCmdLine containsCIS "( $ShellId[1]+$ShellId[13]+'x')" OR TgtProcCmdLine = "*( $PSHome[*]+$PSHOME[*]+*" OR TgtProcCmdLine containsCIS "( $env:Public[13]+$env:Public[5]+'x')" OR TgtProcCmdLine = "*( $env:ComSpec[4,*,25]-Join'')*" OR TgtProcCmdLine containsCIS "[1,3]+'x'-Join'')") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```