# proc_creation_win_powershell_download_com_cradles

## Title
Potential COM Objects Download Cradles Usage - Process Creation

## ID
02b64f1b-3f33-4e67-aede-ef3b0a5a8fcf

## Author
frack113

## Date
2022-12-25

## Tags
attack.command-and-control, attack.t1105

## Description
Detects usage of COM objects that can be abused to download files in PowerShell by CLSID

## References
https://learn.microsoft.com/en-us/dotnet/api/system.type.gettypefromclsid?view=net-7.0
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=57

## False Positives
Legitimate use of the library

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "[Type]::GetTypeFromCLSID(" AND (TgtProcCmdLine containsCIS "0002DF01-0000-0000-C000-000000000046" OR TgtProcCmdLine containsCIS "F6D90F16-9C73-11D3-B32E-00C04F990BB4" OR TgtProcCmdLine containsCIS "F5078F35-C551-11D3-89B9-0000F81FE221" OR TgtProcCmdLine containsCIS "88d96a0a-f192-11d4-a65f-0040963251e5" OR TgtProcCmdLine containsCIS "AFBA6B42-5692-48EA-8141-DC517DCF0EF1" OR TgtProcCmdLine containsCIS "AFB40FFD-B609-40A3-9828-F88BBE11E4E3" OR TgtProcCmdLine containsCIS "88d96a0b-f192-11d4-a65f-0040963251e5" OR TgtProcCmdLine containsCIS "2087c2f4-2cef-4953-a8ab-66779b670495" OR TgtProcCmdLine containsCIS "000209FF-0000-0000-C000-000000000046" OR TgtProcCmdLine containsCIS "00024500-0000-0000-C000-000000000046")))

```