# registry_set_sip_persistence

## Title
Persistence Via New SIP Provider

## ID
5a2b21ee-6aaa-4234-ac9d-59a59edf90a1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence, attack.defense-evasion, attack.t1553.003

## Description
Detects when an attacker register a new SIP provider for persistence and defense evasion

## References
https://persistence-info.github.io/Data/codesigning.html
https://github.com/gtworek/PSBits/tree/master/SIP
https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf

## False Positives
Legitimate SIP being registered by the OS or different software.

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryKeyPath containsCIS "\Dll" OR RegistryKeyPath containsCIS "\$DLL") AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Cryptography\Providers\" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Cryptography\OID\EncodingType" OR RegistryKeyPath containsCIS "\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\" OR RegistryKeyPath containsCIS "\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType")) AND (NOT ((RegistryValue In Contains AnyCase ("WINTRUST.DLL","mso.dll")) OR (RegistryValue = "C:\Windows\System32\PsfSip.dll" AND SrcProcImagePath = "C:\Windows\System32\poqexec.exe" AND RegistryKeyPath containsCIS "\CryptSIPDll")))))

```