# registry_set_uac_bypass_sdclt

## Title
UAC Bypass via Sdclt

## ID
5b872a46-3b90-45c1-8419-f675db8053aa

## Author
Omer Yampel, Christian Burkard (Nextron Systems)

## Date
2017-03-17

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002, car.2019-04-001

## Description
Detects the pattern of UAC Bypass using registry key manipulation of sdclt.exe (e.g. UACMe 53)

## References
https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "Software\Classes\exefile\shell\runas\command\isolatedCommand" OR (RegistryValue RegExp "-1[0-9]{3}\\\\Software\\\\Classes\\\\" AND RegistryKeyPath endswithCIS "Software\Classes\Folder\shell\open\command\SymbolicLinkValue")))

```