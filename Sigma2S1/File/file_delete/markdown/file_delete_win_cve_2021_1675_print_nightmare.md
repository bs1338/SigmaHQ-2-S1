# file_delete_win_cve_2021_1675_print_nightmare

## Title
Potential PrintNightmare Exploitation Attempt

## ID
5b2bbc47-dead-4ef7-8908-0cf73fcbecbf

## Author
Bhabesh Raj

## Date
2021-07-01

## Tags
attack.persistence, attack.defense-evasion, attack.privilege-escalation, attack.t1574, cve.2021-1675

## Description
Detect DLL deletions from Spooler Service driver folder. This might be a potential exploitation attempt of CVE-2021-1675

## References
https://web.archive.org/web/20210629055600/https://github.com/hhlxf/PrintNightmare/
https://github.com/cube0x0/CVE-2021-1675

## False Positives
Unknown

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\spoolsv.exe" AND TgtFilePath containsCIS "C:\Windows\System32\spool\drivers\x64\3\"))

```