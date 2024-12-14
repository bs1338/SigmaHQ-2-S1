# registry_set_asep_reg_keys_modification_wow6432node

## Title
Wow6432Node CurrentVersion Autorun Keys Modification

## ID
b29aed60-ebd1-442b-9cb5-16a1d0324adb

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
https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/

## False Positives
Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason
Legitimate administrator sets up autorun keys for legitimate reason

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion" AND (RegistryKeyPath containsCIS "\ShellServiceObjectDelayLoad" OR RegistryKeyPath containsCIS "\Run\" OR RegistryKeyPath containsCIS "\RunOnce\" OR RegistryKeyPath containsCIS "\RunOnceEx\" OR RegistryKeyPath containsCIS "\RunServices\" OR RegistryKeyPath containsCIS "\RunServicesOnce\" OR RegistryKeyPath containsCIS "\Explorer\ShellServiceObjects" OR RegistryKeyPath containsCIS "\Explorer\ShellIconOverlayIdentifiers" OR RegistryKeyPath containsCIS "\Explorer\ShellExecuteHooks" OR RegistryKeyPath containsCIS "\Explorer\SharedTaskScheduler" OR RegistryKeyPath containsCIS "\Explorer\Browser Helper Objects")) AND (NOT ((RegistryValue endswithCIS ".exe\" /burn.runonce" AND RegistryValue startswithCIS "\"C:\ProgramData\Package Cache\" AND SrcProcImagePath containsCIS "\windowsdesktop-runtime-" AND (RegistryKeyPath endswithCIS "\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\{e2d1ae32-dd1d-4ad7-a298-10e42e7840fc}" OR RegistryKeyPath endswithCIS "\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\{7037b699-7382-448c-89a7-4765961d2537}")) OR (RegistryValue endswithCIS "-A251-47B7-93E1-CDD82E34AF8B}" OR RegistryValue = "grpconv -o" OR (RegistryValue containsCIS "C:\Program Files" AND RegistryValue containsCIS "\Dropbox\Client\Dropbox.exe" AND RegistryValue containsCIS " /systemstartup")) OR (SrcProcImagePath containsCIS "C:\Program Files (x86)\Microsoft\EdgeUpdate\Install\{" AND SrcProcImagePath containsCIS "\setup.exe") OR RegistryValue = "(Empty)" OR RegistryKeyPath endswithCIS "\Explorer\Browser Helper Objects\{92EF2EAD-A7CE-4424-B0DB-499CF856608E}\NoExplorer" OR RegistryValue startswithCIS "\"C:\ProgramData\Package Cache\{d21a4f20-968a-4b0c-bf04-a38da5f06e41}\windowsdesktop-runtime-" OR (SrcProcImagePath = "C:\WINDOWS\system32\msiexec.exe" AND RegistryKeyPath containsCIS "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\") OR (SrcProcImagePath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe" AND RegistryKeyPath containsCIS "\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\") OR ((SrcProcImagePath In Contains AnyCase ("C:\Program Files\Microsoft Office\root\integration\integrator.exe","C:\Program Files (x86)\Microsoft Office\root\integration\integrator.exe")) AND RegistryKeyPath containsCIS "\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}\") OR (SrcProcImagePath endswithCIS "\OfficeClickToRun.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\" OR SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\Updates\")) OR (SrcProcImagePath startswithCIS "C:\Windows\Installer\MSI" AND RegistryKeyPath containsCIS "\Explorer\Browser Helper Objects") OR (RegistryValue endswithCIS " /burn.runonce" AND (SrcProcImagePath containsCIS "\winsdksetup.exe" OR SrcProcImagePath containsCIS "\windowsdesktop-runtime-" OR SrcProcImagePath containsCIS "\AspNetCoreSharedFrameworkBundle-") AND (SrcProcImagePath startswithCIS "C:\ProgramData\Package Cache" OR SrcProcImagePath startswithCIS "C:\Windows\Temp\")) OR (RegistryValue endswithCIS "}\VC_redist.x64.exe\" /burn.runonce" AND SrcProcImagePath endswithCIS "\VC_redist.x64.exe")))))

```