# proc_creation_win_netsh_fw_allow_program_in_susp_location

## Title
Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE

## ID
a35f5a72-f347-4e36-8895-9869b0d5fc6d

## Author
Sander Wiebing, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community

## Date
2020-05-25

## Tags
attack.defense-evasion, attack.t1562.004

## Description
Detects Netsh command execution that whitelists a program located in a suspicious location in the Windows Firewall

## References
https://www.virusradar.com/en/Win32_Kasidet.AD/description
https://www.hybrid-analysis.com/sample/07e789f4f2f3259e7559fdccb36e96814c2dbff872a21e1fa03de9ee377d581f?environmentId=100

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "firewall" AND TgtProcCmdLine containsCIS "add" AND TgtProcCmdLine containsCIS "allowedprogram") OR (TgtProcCmdLine containsCIS "advfirewall" AND TgtProcCmdLine containsCIS "firewall" AND TgtProcCmdLine containsCIS "add" AND TgtProcCmdLine containsCIS "rule" AND TgtProcCmdLine containsCIS "action=allow" AND TgtProcCmdLine containsCIS "program=")) AND TgtProcImagePath endswithCIS "\netsh.exe" AND (TgtProcCmdLine containsCIS ":\$Recycle.bin\" OR TgtProcCmdLine containsCIS ":\RECYCLER.BIN\" OR TgtProcCmdLine containsCIS ":\RECYCLERS.BIN\" OR TgtProcCmdLine containsCIS ":\SystemVolumeInformation\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Users\Default\" OR TgtProcCmdLine containsCIS ":\Users\Desktop\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\addins\" OR TgtProcCmdLine containsCIS ":\Windows\cursors\" OR TgtProcCmdLine containsCIS ":\Windows\debug\" OR TgtProcCmdLine containsCIS ":\Windows\drivers\" OR TgtProcCmdLine containsCIS ":\Windows\fonts\" OR TgtProcCmdLine containsCIS ":\Windows\help\" OR TgtProcCmdLine containsCIS ":\Windows\system32\tasks\" OR TgtProcCmdLine containsCIS ":\Windows\Tasks\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\Downloads\" OR TgtProcCmdLine containsCIS "\Local Settings\Temporary Internet Files\" OR TgtProcCmdLine containsCIS "\Temporary Internet Files\Content.Outlook\" OR TgtProcCmdLine containsCIS "%Public%\" OR TgtProcCmdLine containsCIS "%TEMP%" OR TgtProcCmdLine containsCIS "%TMP%")))

```