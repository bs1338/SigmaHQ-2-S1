# proc_creation_win_regsvr32_susp_parent

## Title
Scripting/CommandLine Process Spawned Regsvr32

## ID
ab37a6ec-6068-432b-a64e-2c7bf95b1d22

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-26

## Tags
attack.defense-evasion, attack.t1218.010

## Description
Detects various command line and scripting engines/processes such as "PowerShell", "Wscript", "Cmd", etc. spawning a "regsvr32" instance.

## References
https://web.archive.org/web/20171001085340/https://subt0x10.blogspot.com/2017/04/bypass-application-whitelisting-script.html
https://app.any.run/tasks/34221348-072d-4b70-93f3-aa71f6ebecad/

## False Positives
Legitimate ".bat", ".hta", ".ps1" or ".vbs" scripts leverage legitimately often. Apply additional filter and exclusions as necessary
Some legitimate Windows services

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\regsvr32.exe" AND (SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\powershell_ise.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\wscript.exe")) AND (NOT (TgtProcCmdLine endswithCIS " /s C:\Windows\System32\RpcProxy\RpcProxy.dll" AND SrcProcImagePath = "C:\Windows\System32\cmd.exe"))))

```