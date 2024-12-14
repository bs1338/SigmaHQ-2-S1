# proc_creation_win_susp_progname

## Title
Suspicious Program Names

## ID
efdd8dd5-cee8-4e59-9390-7d4d5e4dd6f6

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-11

## Tags
attack.execution, attack.t1059

## Description
Detects suspicious patterns in program names or folders that are often found in malicious samples or hacktools

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md

## False Positives
Legitimate tools that accidentally match on the searched patterns

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "inject.ps1" OR TgtProcCmdLine containsCIS "Invoke-CVE" OR TgtProcCmdLine containsCIS "pupy.ps1" OR TgtProcCmdLine containsCIS "payload.ps1" OR TgtProcCmdLine containsCIS "beacon.ps1" OR TgtProcCmdLine containsCIS "PowerView.ps1" OR TgtProcCmdLine containsCIS "bypass.ps1" OR TgtProcCmdLine containsCIS "obfuscated.ps1" OR TgtProcCmdLine containsCIS "obfusc.ps1" OR TgtProcCmdLine containsCIS "obfus.ps1" OR TgtProcCmdLine containsCIS "obfs.ps1" OR TgtProcCmdLine containsCIS "evil.ps1" OR TgtProcCmdLine containsCIS "MiniDogz.ps1" OR TgtProcCmdLine containsCIS "_enc.ps1" OR TgtProcCmdLine containsCIS "\shell.ps1" OR TgtProcCmdLine containsCIS "\rshell.ps1" OR TgtProcCmdLine containsCIS "revshell.ps1" OR TgtProcCmdLine containsCIS "\av.ps1" OR TgtProcCmdLine containsCIS "\av_test.ps1" OR TgtProcCmdLine containsCIS "adrecon.ps1" OR TgtProcCmdLine containsCIS "mimikatz.ps1" OR TgtProcCmdLine containsCIS "\PowerUp_" OR TgtProcCmdLine containsCIS "powerup.ps1" OR TgtProcCmdLine containsCIS "\Temp\a.ps1" OR TgtProcCmdLine containsCIS "\Temp\p.ps1" OR TgtProcCmdLine containsCIS "\Temp\1.ps1" OR TgtProcCmdLine containsCIS "Hound.ps1" OR TgtProcCmdLine containsCIS "encode.ps1" OR TgtProcCmdLine containsCIS "powercat.ps1") OR ((TgtProcImagePath containsCIS "\CVE-202" OR TgtProcImagePath containsCIS "\CVE202") OR (TgtProcImagePath endswithCIS "\poc.exe" OR TgtProcImagePath endswithCIS "\artifact.exe" OR TgtProcImagePath endswithCIS "\artifact64.exe" OR TgtProcImagePath endswithCIS "\artifact_protected.exe" OR TgtProcImagePath endswithCIS "\artifact32.exe" OR TgtProcImagePath endswithCIS "\artifact32big.exe" OR TgtProcImagePath endswithCIS "obfuscated.exe" OR TgtProcImagePath endswithCIS "obfusc.exe" OR TgtProcImagePath endswithCIS "\meterpreter"))))

```