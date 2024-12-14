# registry_event_mimikatz_printernightmare

## Title
PrinterNightmare Mimikatz Driver Name

## ID
ba6b9e43-1d45-4d3c-a504-1043a64c8469

## Author
Markus Neis, @markus_neis, Florian Roth

## Date
2021-07-04

## Tags
attack.execution, attack.t1204, cve.2021-1675, cve.2021-34527

## Description
Detects static QMS 810 and mimikatz driver name used by Mimikatz as exploited in CVE-2021-1675 and CVE-2021-34527

## References
https://github.com/gentilkiwi/mimikatz/commit/c21276072b3f2a47a21e215a46962a17d54b3760
https://www.lexjansen.com/sesug/1993/SESUG93035.pdf
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/4464eaf0-f34f-40d5-b970-736437a21913
https://nvd.nist.gov/vuln/detail/cve-2021-1675
https://nvd.nist.gov/vuln/detail/cve-2021-34527

## False Positives
Legitimate installation of printer driver QMS 810, Texas Instruments microLaser printer (unlikely)

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Control\Print\Environments\Windows x64\Drivers\Version-3\QMS 810\" OR RegistryKeyPath containsCIS "\Control\Print\Environments\Windows x64\Drivers\Version-3\mimikatz") OR (RegistryKeyPath containsCIS "legitprinter" AND RegistryKeyPath containsCIS "\Control\Print\Environments\Windows") OR ((RegistryKeyPath containsCIS "\Control\Print\Environments" OR RegistryKeyPath containsCIS "\CurrentVersion\Print\Printers") AND (RegistryKeyPath containsCIS "Gentil Kiwi" OR RegistryKeyPath containsCIS "mimikatz printer" OR RegistryKeyPath containsCIS "Kiwi Legit Printer"))))

```