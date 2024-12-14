# proc_creation_win_sdiagnhost_susp_child

## Title
Sdiagnhost Calling Suspicious Child Process

## ID
f3d39c45-de1a-4486-a687-ab126124f744

## Author
Nextron Systems, @Kostastsale

## Date
2022-06-01

## Tags
attack.defense-evasion, attack.t1036, attack.t1218

## Description
Detects sdiagnhost.exe calling a suspicious child process (e.g. used in exploits for Follina / CVE-2022-30190)

## References
https://twitter.com/nao_sec/status/1530196847679401984
https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e
https://app.any.run/tasks/713f05d2-fe78-4b9d-a744-f7c133e3fafb/
https://app.any.run/tasks/f420d295-0457-4e9b-9b9e-6732be227583/
https://app.any.run/tasks/c4117d9a-f463-461a-b90f-4cd258746798/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\taskkill.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\calc.exe") AND SrcProcImagePath endswithCIS "\sdiagnhost.exe") AND (NOT ((TgtProcCmdLine containsCIS "bits" AND TgtProcImagePath endswithCIS "\cmd.exe") OR ((TgtProcCmdLine endswithCIS "-noprofile -" OR TgtProcCmdLine endswithCIS "-noprofile") AND TgtProcImagePath endswithCIS "\powershell.exe")))))

```