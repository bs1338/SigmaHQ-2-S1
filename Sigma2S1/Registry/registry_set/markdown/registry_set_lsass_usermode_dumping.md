# registry_set_lsass_usermode_dumping

## Title
Lsass Full Dump Request Via DumpType Registry Settings

## ID
33efc23c-6ea2-4503-8cfe-bdf82ce8f719

## Author
@pbssubhash

## Date
2022-12-08

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects the setting of the "DumpType" registry value to "2" which stands for a "Full Dump". Technique such as LSASS Shtinkering requires this value to be "2" in order to dump LSASS.

## References
https://github.com/deepinstinct/Lsass-Shtinkering
https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps
https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf

## False Positives
Legitimate application that needs to do a full dump of their process

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000002)" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\DumpType" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\lsass.exe\DumpType")))

```