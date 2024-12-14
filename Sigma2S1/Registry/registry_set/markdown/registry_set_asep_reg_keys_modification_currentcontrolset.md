# registry_set_asep_reg_keys_modification_currentcontrolset

## Title
CurrentControlSet Autorun Keys Modification

## ID
f674e36a-4b91-431e-8aef-f8a96c2aca35

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
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\SYSTEM\CurrentControlSet\Control" AND (RegistryKeyPath containsCIS "\Terminal Server\WinStations\RDP-Tcp\InitialProgram" OR RegistryKeyPath containsCIS "\Terminal Server\Wds\rdpwd\StartupPrograms" OR RegistryKeyPath containsCIS "\SecurityProviders\SecurityProviders" OR RegistryKeyPath containsCIS "\SafeBoot\AlternateShell" OR RegistryKeyPath containsCIS "\Print\Providers" OR RegistryKeyPath containsCIS "\Print\Monitors" OR RegistryKeyPath containsCIS "\NetworkProvider\Order" OR RegistryKeyPath containsCIS "\Lsa\Notification Packages" OR RegistryKeyPath containsCIS "\Lsa\Authentication Packages" OR RegistryKeyPath containsCIS "\BootVerificationProgram\ImagePath")) AND (NOT (((RegistryValue In Contains AnyCase ("cpwmon64_v40.dll","CutePDF Writer")) AND SrcProcImagePath = "C:\Windows\System32\spoolsv.exe" AND RegistryKeyPath containsCIS "\Print\Monitors\CutePDF Writer Monitor") OR RegistryValue = "(Empty)" OR (SrcProcImagePath = "C:\Windows\System32\spoolsv.exe" AND RegistryKeyPath containsCIS "Print\Monitors\Appmon\Ports\Microsoft.Office.OneNote_" AND (User containsCIS "AUTHORI" OR User containsCIS "AUTORI")) OR (SrcProcImagePath = "C:\Windows\System32\poqexec.exe" AND RegistryKeyPath endswithCIS "\NetworkProvider\Order\ProviderOrder") OR (RegistryValue = "VNCpm.dll" AND SrcProcImagePath = "C:\Windows\System32\spoolsv.exe" AND RegistryKeyPath endswithCIS "\Print\Monitors\MONVNC\Driver")))))

```