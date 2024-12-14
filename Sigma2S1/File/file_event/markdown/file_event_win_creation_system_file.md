# file_event_win_creation_system_file

## Title
Files With System Process Name In Unsuspected Locations

## ID
d5866ddf-ce8f-4aea-b28e-d96485a20d3d

## Author
Sander Wiebing, Tim Shelton, Nasreddine Bencherchali (Nextron Systems)

## Date
2020-05-26

## Tags
attack.defense-evasion, attack.t1036.005

## Description
Detects the creation of an executable with a system process name in folders other than the system ones (System32, SysWOW64, etc.).
It is highly recommended to perform an initial baseline before using this rule in production.


## References
Internal Research

## False Positives
System processes copied outside their default folders for testing purposes
Third party software naming their software with the same names as the processes mentioned here

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\AtBroker.exe" OR TgtFilePath endswithCIS "\audiodg.exe" OR TgtFilePath endswithCIS "\backgroundTaskHost.exe" OR TgtFilePath endswithCIS "\bcdedit.exe" OR TgtFilePath endswithCIS "\bitsadmin.exe" OR TgtFilePath endswithCIS "\cmdl32.exe" OR TgtFilePath endswithCIS "\cmstp.exe" OR TgtFilePath endswithCIS "\conhost.exe" OR TgtFilePath endswithCIS "\csrss.exe" OR TgtFilePath endswithCIS "\dasHost.exe" OR TgtFilePath endswithCIS "\dfrgui.exe" OR TgtFilePath endswithCIS "\dllhost.exe" OR TgtFilePath endswithCIS "\dwm.exe" OR TgtFilePath endswithCIS "\eventcreate.exe" OR TgtFilePath endswithCIS "\eventvwr.exe" OR TgtFilePath endswithCIS "\explorer.exe" OR TgtFilePath endswithCIS "\extrac32.exe" OR TgtFilePath endswithCIS "\fontdrvhost.exe" OR TgtFilePath endswithCIS "\ipconfig.exe" OR TgtFilePath endswithCIS "\iscsicli.exe" OR TgtFilePath endswithCIS "\iscsicpl.exe" OR TgtFilePath endswithCIS "\logman.exe" OR TgtFilePath endswithCIS "\LogonUI.exe" OR TgtFilePath endswithCIS "\LsaIso.exe" OR TgtFilePath endswithCIS "\lsass.exe" OR TgtFilePath endswithCIS "\lsm.exe" OR TgtFilePath endswithCIS "\msiexec.exe" OR TgtFilePath endswithCIS "\msinfo32.exe" OR TgtFilePath endswithCIS "\mstsc.exe" OR TgtFilePath endswithCIS "\nbtstat.exe" OR TgtFilePath endswithCIS "\odbcconf.exe" OR TgtFilePath endswithCIS "\powershell.exe" OR TgtFilePath endswithCIS "\pwsh.exe" OR TgtFilePath endswithCIS "\regini.exe" OR TgtFilePath endswithCIS "\regsvr32.exe" OR TgtFilePath endswithCIS "\rundll32.exe" OR TgtFilePath endswithCIS "\RuntimeBroker.exe" OR TgtFilePath endswithCIS "\schtasks.exe" OR TgtFilePath endswithCIS "\SearchFilterHost.exe" OR TgtFilePath endswithCIS "\SearchIndexer.exe" OR TgtFilePath endswithCIS "\SearchProtocolHost.exe" OR TgtFilePath endswithCIS "\SecurityHealthService.exe" OR TgtFilePath endswithCIS "\SecurityHealthSystray.exe" OR TgtFilePath endswithCIS "\services.exe" OR TgtFilePath endswithCIS "\ShellAppRuntime.exe" OR TgtFilePath endswithCIS "\sihost.exe" OR TgtFilePath endswithCIS "\smartscreen.exe" OR TgtFilePath endswithCIS "\smss.exe" OR TgtFilePath endswithCIS "\spoolsv.exe" OR TgtFilePath endswithCIS "\svchost.exe" OR TgtFilePath endswithCIS "\SystemSettingsBroker.exe" OR TgtFilePath endswithCIS "\taskhost.exe" OR TgtFilePath endswithCIS "\taskhostw.exe" OR TgtFilePath endswithCIS "\Taskmgr.exe" OR TgtFilePath endswithCIS "\TiWorker.exe" OR TgtFilePath endswithCIS "\vssadmin.exe" OR TgtFilePath endswithCIS "\w32tm.exe" OR TgtFilePath endswithCIS "\WerFault.exe" OR TgtFilePath endswithCIS "\WerFaultSecure.exe" OR TgtFilePath endswithCIS "\wermgr.exe" OR TgtFilePath endswithCIS "\wevtutil.exe" OR TgtFilePath endswithCIS "\wininit.exe" OR TgtFilePath endswithCIS "\winlogon.exe" OR TgtFilePath endswithCIS "\winrshost.exe" OR TgtFilePath endswithCIS "\WinRTNetMUAHostServer.exe" OR TgtFilePath endswithCIS "\wlanext.exe" OR TgtFilePath endswithCIS "\wlrmdr.exe" OR TgtFilePath endswithCIS "\WmiPrvSE.exe" OR TgtFilePath endswithCIS "\wslhost.exe" OR TgtFilePath endswithCIS "\WSReset.exe" OR TgtFilePath endswithCIS "\WUDFHost.exe" OR TgtFilePath endswithCIS "\WWAHost.exe") AND (NOT (TgtFilePath endswithCIS "C:\Windows\explorer.exe" OR (TgtFilePath containsCIS "C:\$WINDOWS.~BT\" OR TgtFilePath containsCIS "C:\$WinREAgent\" OR TgtFilePath containsCIS "C:\Windows\SoftwareDistribution\" OR TgtFilePath containsCIS "C:\Windows\System32\" OR TgtFilePath containsCIS "C:\Windows\SysWOW64\" OR TgtFilePath containsCIS "C:\Windows\WinSxS\" OR TgtFilePath containsCIS "C:\Windows\uus\") OR (SrcProcImagePath endswithCIS "\SecurityHealthSetup.exe" AND TgtFilePath containsCIS "C:\Windows\System32\SecurityHealth\" AND TgtFilePath endswithCIS "\SecurityHealthSystray.exe") OR (SrcProcImagePath endswithCIS "C:\WINDOWS\system32\msiexec.exe" AND (TgtFilePath endswithCIS "C:\Program Files\PowerShell\7\pwsh.exe" OR TgtFilePath endswithCIS "C:\Program Files\PowerShell\7-preview\pwsh.exe")) OR (SrcProcImagePath endswithCIS "C:\Windows\system32\svchost.exe" AND TgtFilePath containsCIS "C:\Program Files\WindowsApps\") OR SrcProcImagePath endswithCIS "C:\Windows\System32\wuauclt.exe"))))

```