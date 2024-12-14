# proc_creation_win_susp_system_exe_anomaly

## Title
System File Execution Location Anomaly

## ID
e4a6b256-3e47-40fc-89d2-7a477edd6915

## Author
Florian Roth (Nextron Systems), Patrick Bareiss, Anton Kutepov, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2017-11-27

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects the execution of a Windows system binary that is usually located in the system folder from an uncommon location.


## References
https://twitter.com/GelosSnake/status/934900723426439170
https://asec.ahnlab.com/en/39828/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\atbroker.exe" OR TgtProcImagePath endswithCIS "\audiodg.exe" OR TgtProcImagePath endswithCIS "\bcdedit.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\certreq.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cmstp.exe" OR TgtProcImagePath endswithCIS "\conhost.exe" OR TgtProcImagePath endswithCIS "\consent.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\csrss.exe" OR TgtProcImagePath endswithCIS "\dashost.exe" OR TgtProcImagePath endswithCIS "\defrag.exe" OR TgtProcImagePath endswithCIS "\dfrgui.exe" OR TgtProcImagePath endswithCIS "\dism.exe" OR TgtProcImagePath endswithCIS "\dllhost.exe" OR TgtProcImagePath endswithCIS "\dllhst3g.exe" OR TgtProcImagePath endswithCIS "\dwm.exe" OR TgtProcImagePath endswithCIS "\eventvwr.exe" OR TgtProcImagePath endswithCIS "\logonui.exe" OR TgtProcImagePath endswithCIS "\LsaIso.exe" OR TgtProcImagePath endswithCIS "\lsass.exe" OR TgtProcImagePath endswithCIS "\lsm.exe" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\ntoskrnl.exe" OR TgtProcImagePath endswithCIS "\powershell_ise.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\runonce.exe" OR TgtProcImagePath endswithCIS "\RuntimeBroker.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\services.exe" OR TgtProcImagePath endswithCIS "\sihost.exe" OR TgtProcImagePath endswithCIS "\smartscreen.exe" OR TgtProcImagePath endswithCIS "\smss.exe" OR TgtProcImagePath endswithCIS "\spoolsv.exe" OR TgtProcImagePath endswithCIS "\svchost.exe" OR TgtProcImagePath endswithCIS "\taskhost.exe" OR TgtProcImagePath endswithCIS "\Taskmgr.exe" OR TgtProcImagePath endswithCIS "\userinit.exe" OR TgtProcImagePath endswithCIS "\wininit.exe" OR TgtProcImagePath endswithCIS "\winlogon.exe" OR TgtProcImagePath endswithCIS "\winver.exe" OR TgtProcImagePath endswithCIS "\wlanext.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\wsl.exe" OR TgtProcImagePath endswithCIS "\wsmprovhost.exe") AND (NOT ((TgtProcImagePath startswithCIS "C:\$WINDOWS.~BT\" OR TgtProcImagePath startswithCIS "C:\$WinREAgent\" OR TgtProcImagePath startswithCIS "C:\Windows\SoftwareDistribution\" OR TgtProcImagePath startswithCIS "C:\Windows\System32\" OR TgtProcImagePath startswithCIS "C:\Windows\SystemTemp\" OR TgtProcImagePath startswithCIS "C:\Windows\SysWOW64\" OR TgtProcImagePath startswithCIS "C:\Windows\uus\" OR TgtProcImagePath startswithCIS "C:\Windows\WinSxS\") OR (TgtProcImagePath In Contains AnyCase ("C:\Program Files\PowerShell\7\pwsh.exe","C:\Program Files\PowerShell\7-preview\pwsh.exe")) OR (TgtProcImagePath endswithCIS "\wsl.exe" AND TgtProcImagePath startswithCIS "C:\Program Files\WindowsApps\MicrosoftCorporationII.WindowsSubsystemForLinux"))) AND (NOT TgtProcImagePath containsCIS "\SystemRoot\System32\")))

```