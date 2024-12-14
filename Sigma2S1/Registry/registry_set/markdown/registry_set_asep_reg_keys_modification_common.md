# registry_set_asep_reg_keys_modification_common

## Title
Common Autorun Keys Modification

## ID
f59c3faf-50f3-464b-9f4c-1b67ab512d99

## Author
Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split), wagga (name)

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
https://persistence-info.github.io/Data/userinitmprlogonscript.html

## False Positives
Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason
Legitimate administrator sets up autorun keys for legitimate reason

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\SOFTWARE\Wow6432Node\Microsoft\Windows CE Services\AutoStart" OR RegistryKeyPath containsCIS "\Software\Wow6432Node\Microsoft\Command Processor\Autorun" OR RegistryKeyPath containsCIS "\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows CE Services\AutoStartOnDisconnect" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows CE Services\AutoStartOnConnect" OR RegistryKeyPath containsCIS "\SYSTEM\Setup\CmdLine" OR RegistryKeyPath containsCIS "\Software\Microsoft\Ctf\LangBarAddin" OR RegistryKeyPath containsCIS "\Software\Microsoft\Command Processor\Autorun" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Active Setup\Installed Components" OR RegistryKeyPath containsCIS "\SOFTWARE\Classes\Protocols\Handler" OR RegistryKeyPath containsCIS "\SOFTWARE\Classes\Protocols\Filter" OR RegistryKeyPath containsCIS "\SOFTWARE\Classes\Htmlfile\Shell\Open\Command\(Default)" OR RegistryKeyPath containsCIS "\Environment\UserInitMprLogonScript" OR RegistryKeyPath containsCIS "\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\Scrnsave.exe" OR RegistryKeyPath containsCIS "\Software\Microsoft\Internet Explorer\UrlSearchHooks" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Internet Explorer\Desktop\Components" OR RegistryKeyPath containsCIS "\Software\Classes\Clsid\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\Inprocserver32" OR RegistryKeyPath containsCIS "\Control Panel\Desktop\Scrnsave.exe") AND (NOT (RegistryKeyPath containsCIS "\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4383}" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" OR RegistryValue = "(Empty)" OR (SrcProcImagePath In Contains AnyCase ("C:\Windows\System32\poqexec.exe","C:\Program Files (x86)\Microsoft Office\root\integration\integrator.exe")) OR ((RegistryKeyPath containsCIS "\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\PROTOCOLS\Handler\" OR RegistryKeyPath containsCIS "\ClickToRunStore\HKMU\SOFTWARE\Classes\PROTOCOLS\Handler\") OR (RegistryValue In Contains AnyCase ("{314111c7-a502-11d2-bbca-00c04f8ec294}","{3459B272-CC19-4448-86C9-DDC3B4B2FAD3}","{42089D2D-912D-4018-9087-2B87803E93FB}","{5504BE45-A83B-4808-900A-3A5C36E7F77A}","{807583E5-5146-11D5-A672-00B0D022E945}"))) OR (SrcProcImagePath endswithCIS "\OfficeClickToRun.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\" OR SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\Updates\"))))))

```