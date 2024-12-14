# proc_creation_win_powershell_encode

## Title
Suspicious Execution of Powershell with Base64

## ID
fb843269-508c-4b76-8b8d-88679db22ce7

## Author
frack113

## Date
2022-01-02

## Tags
attack.execution, attack.t1059.001

## Description
Commandline to launch powershell with a base64 payload

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.001/T1059.001.md#atomic-test-20---powershell-invoke-known-malicious-cmdlets
https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/
https://mikefrobbins.com/2017/06/15/simple-obfuscation-with-powershell-using-base64-encoding/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -e " OR TgtProcCmdLine containsCIS " -en " OR TgtProcCmdLine containsCIS " -enc " OR TgtProcCmdLine containsCIS " -enco" OR TgtProcCmdLine containsCIS " -ec ") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")) AND (NOT ((SrcProcImagePath containsCIS "C:\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows\" OR SrcProcImagePath containsCIS "\gc_worker.exe") OR TgtProcCmdLine containsCIS " -Encoding "))))

```