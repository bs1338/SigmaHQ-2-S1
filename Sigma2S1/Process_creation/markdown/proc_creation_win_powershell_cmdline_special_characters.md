# proc_creation_win_powershell_cmdline_special_characters

## Title
Potential PowerShell Command Line Obfuscation

## ID
d7bcd677-645d-4691-a8d4-7a5602b780d1

## Author
Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton (fp)

## Date
2020-10-15

## Tags
attack.execution, attack.defense-evasion, attack.t1027, attack.t1059.001

## Description
Detects the PowerShell command lines with special characters

## References
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=64

## False Positives
Amazon SSM Document Worker
Windows Defender ATP

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (TgtProcCmdLine RegExp "\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+" OR TgtProcCmdLine RegExp "\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{" OR TgtProcCmdLine RegExp "\\^.*\\^.*\\^.*\\^.*\\^" OR TgtProcCmdLine RegExp "`.*`.*`.*`.*`")) AND (NOT (SrcProcImagePath = "C:\Program Files\Amazon\SSM\ssm-document-worker.exe" OR (TgtProcCmdLine containsCIS "new EventSource(\"Microsoft.Windows.Sense.Client.Management\"" OR TgtProcCmdLine containsCIS "public static extern bool InstallELAMCertificateInfo(SafeFileHandle handle);")))))

```