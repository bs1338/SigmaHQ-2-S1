# registry_set_asep_reg_keys_modification_currentversion_nt

## Title
CurrentVersion NT Autorun Keys Modification

## ID
cbf93e5d-ca6c-4722-8bea-e9119007c248

## Author
Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)

## Date
2019-10-25

## Tags
attack.persistence, attack.t1547.001

## Description
Detects modification of autostart extensibility point (ASEP) in registry.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

## False Positives
Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason
Legitimate administrator sets up autorun keys for legitimate reason

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion" AND (RegistryKeyPath containsCIS "\Winlogon\VmApplet" OR RegistryKeyPath containsCIS "\Winlogon\Userinit" OR RegistryKeyPath containsCIS "\Winlogon\Taskman" OR RegistryKeyPath containsCIS "\Winlogon\Shell" OR RegistryKeyPath containsCIS "\Winlogon\GpExtensions" OR RegistryKeyPath containsCIS "\Winlogon\AppSetup" OR RegistryKeyPath containsCIS "\Winlogon\AlternateShells\AvailableShells" OR RegistryKeyPath containsCIS "\Windows\IconServiceLib" OR RegistryKeyPath containsCIS "\Windows\Appinit_Dlls" OR RegistryKeyPath containsCIS "\Image File Execution Options" OR RegistryKeyPath containsCIS "\Font Drivers" OR RegistryKeyPath containsCIS "\Drivers32" OR RegistryKeyPath containsCIS "\Windows\Run" OR RegistryKeyPath containsCIS "\Windows\Load") AND (NOT ((SrcProcImagePath endswithCIS "\MicrosoftEdgeUpdate.exe" AND SrcProcImagePath startswithCIS "C:\Program Files (x86)\Microsoft\Temp\") OR RegistryValue = "(Empty)" OR (RegistryKeyPath containsCIS "\Image File Execution Options\" AND (RegistryKeyPath endswithCIS "\DisableExceptionChainValidation" OR RegistryKeyPath endswithCIS "\MitigationOptions")) OR ((RegistryKeyPath containsCIS "\ClickToRunStore\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" OR RegistryKeyPath containsCIS "\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Windows NT\CurrentVersion\") OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files\Microsoft Office\root\integration\integrator.exe","C:\Program Files (x86)\Microsoft Office\root\integration\integrator.exe"))) OR (SrcProcImagePath endswithCIS "\ngen.exe" AND SrcProcImagePath startswithCIS "C:\Windows\Microsoft.NET\Framework") OR (SrcProcImagePath endswithCIS "\OfficeClickToRun.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\" OR SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\Updates\")) OR (RegistryValue endswithCIS "\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe\"" AND RegistryValue startswithCIS "C:\Windows\system32\cmd.exe /q /c del /q \"C:\Users\" AND SrcProcImagePath endswithCIS "\AppData\Local\Microsoft\OneDrive\StandaloneUpdater\OneDriveSetup.exe" AND RegistryKeyPath endswithCIS "\Microsoft\Windows\CurrentVersion\RunOnce\Delete Cached Update Binary") OR ((RegistryValue In Contains AnyCase ("DWORD (0x00000009)","DWORD (0x000003c0)")) AND SrcProcImagePath = "C:\Windows\system32\svchost.exe" AND (RegistryKeyPath containsCIS "\Winlogon\GPExtensions\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\PreviousPolicyAreas" OR RegistryKeyPath containsCIS "\Winlogon\GPExtensions\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\MaxNoGPOListChangesInterval"))))))

```