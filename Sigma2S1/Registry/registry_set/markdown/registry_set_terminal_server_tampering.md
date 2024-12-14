# registry_set_terminal_server_tampering

## Title
RDP Sensitive Settings Changed

## ID
3f6b7b62-61aa-45db-96bd-9c31b36b653c

## Author
Samir Bousseaden, David ANDRE, Roberto Rodriguez @Cyb3rWard0g, Nasreddine Bencherchali

## Date
2022-08-06

## Tags
attack.defense-evasion, attack.persistence, attack.t1112

## Description
Detects tampering of RDP Terminal Service/Server sensitive settings.
 Such as allowing unauthorized users access to a system via the 'fAllowUnsolicited' or enabling RDP via 'fDenyTSConnections'...etc


## References
https://web.archive.org/web/20200929062532/https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html
http://woshub.com/rds-shadow-how-to-connect-to-a-user-session-in-windows-server-2012-r2/
https://twitter.com/SagieSec/status/1469001618863624194?t=HRf0eA0W1YYzkTSHb-Ky1A&s=03
https://threathunterplaybook.com/hunts/windows/190407-RegModEnableRDPConnections/notebook.html
https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/
http://etutorials.org/Microsoft+Products/microsoft+windows+server+2003+terminal+services/Chapter+6+Registry/Registry+Keys+for+Terminal+Services/
https://admx.help/HKLM/SOFTWARE/Policies/Microsoft/Windows%20NT/Terminal%20Services
https://blog.sekoia.io/darkgate-internals/
https://github.com/redcanaryco/atomic-red-team/blob/02c7d02fe1f1feb0fc7944550408ea8224273994/atomics/T1112/T1112.md#atomic-test-63---disable-remote-desktop-anti-alias-setting-through-registry
https://github.com/redcanaryco/atomic-red-team/blob/02c7d02fe1f1feb0fc7944550408ea8224273994/atomics/T1112/T1112.md#atomic-test-64---disable-remote-desktop-security-settings-through-registry

## False Positives
Some of the keys mentioned here could be modified by an administrator while setting group policy (it should be investigated either way)

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryValue In Contains AnyCase ("DWORD (0x00000001)","DWORD (0x00000002)","DWORD (0x00000003)","DWORD (0x00000004)")) AND (RegistryKeyPath containsCIS "\Control\Terminal Server\" OR RegistryKeyPath containsCIS "\Windows NT\Terminal Services\") AND RegistryKeyPath endswithCIS "\Shadow") OR (RegistryValue = "DWORD (0x00000001)" AND (RegistryKeyPath containsCIS "\Control\Terminal Server\" OR RegistryKeyPath containsCIS "\Windows NT\Terminal Services\") AND (RegistryKeyPath endswithCIS "\DisableRemoteDesktopAntiAlias" OR RegistryKeyPath endswithCIS "\DisableSecuritySettings" OR RegistryKeyPath endswithCIS "\fAllowUnsolicited" OR RegistryKeyPath endswithCIS "\fAllowUnsolicitedFullControl")) OR (RegistryKeyPath containsCIS "\Control\Terminal Server\InitialProgram" OR RegistryKeyPath containsCIS "\Control\Terminal Server\WinStations\RDP-Tcp\InitialProgram" OR RegistryKeyPath containsCIS "\services\TermService\Parameters\ServiceDll" OR RegistryKeyPath containsCIS "\Windows NT\Terminal Services\InitialProgram")))

```