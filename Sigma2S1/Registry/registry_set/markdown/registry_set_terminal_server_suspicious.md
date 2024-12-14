# registry_set_terminal_server_suspicious

## Title
RDP Sensitive Settings Changed to Zero

## ID
a2863fbc-d5cb-48d5-83fb-d976d4b1743b

## Author
Samir Bousseaden, David ANDRE, Roberto Rodriguez @Cyb3rWard0g, Nasreddine Bencherchali

## Date
2022-09-29

## Tags
attack.defense-evasion, attack.persistence, attack.t1112

## Description
Detects tampering of RDP Terminal Service/Server sensitive settings.
 Such as allowing unauthorized users access to a system via the 'fAllowUnsolicited' or enabling RDP via 'fDenyTSConnections', etc.


## References
https://web.archive.org/web/20200929062532/https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html
http://woshub.com/rds-shadow-how-to-connect-to-a-user-session-in-windows-server-2012-r2/
https://twitter.com/SagieSec/status/1469001618863624194?t=HRf0eA0W1YYzkTSHb-Ky1A&s=03
https://threathunterplaybook.com/hunts/windows/190407-RegModEnableRDPConnections/notebook.html
https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/
http://etutorials.org/Microsoft+Products/microsoft+windows+server+2003+terminal+services/Chapter+6+Registry/Registry+Keys+for+Terminal+Services/
https://admx.help/HKLM/SOFTWARE/Policies/Microsoft/Windows%20NT/Terminal%20Services

## False Positives
Some of the keys mentioned here could be modified by an administrator while setting group policy (it should be investigated either way)

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath endswithCIS "\fDenyTSConnections" OR RegistryKeyPath endswithCIS "\fSingleSessionPerUser" OR RegistryKeyPath endswithCIS "\UserAuthentication")))

```