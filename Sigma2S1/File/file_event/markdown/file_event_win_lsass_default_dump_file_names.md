# file_event_win_lsass_default_dump_file_names

## Title
LSASS Process Memory Dump Files

## ID
a5a2d357-1ab8-4675-a967-ef9990a59391

## Author
Florian Roth (Nextron Systems)

## Date
2021-11-15

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects creation of files with names used by different memory dumping tools to create a memory dump of the LSASS process memory, which contains user credentials.

## References
https://www.google.com/search?q=procdump+lsass
https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf
https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/windows/credential_access_lsass_memdump_file_created.toml
https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/
https://github.com/helpsystems/nanodump
https://github.com/CCob/MirrorDump
https://github.com/safedv/RustiveDump/blob/1a9b026b477587becfb62df9677cede619d42030/src/main.rs#L35
https://github.com/ricardojoserf/NativeDump/blob/01d8cd17f31f51f5955a38e85cd3c83a17596175/NativeDump/Program.cs#L258

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\Andrew.dmp" OR TgtFilePath endswithCIS "\Coredump.dmp" OR TgtFilePath endswithCIS "\lsass.dmp" OR TgtFilePath endswithCIS "\lsass.rar" OR TgtFilePath endswithCIS "\lsass.zip" OR TgtFilePath endswithCIS "\NotLSASS.zip" OR TgtFilePath endswithCIS "\PPLBlade.dmp" OR TgtFilePath endswithCIS "\rustive.dmp") OR (TgtFilePath containsCIS "\lsass_2" OR TgtFilePath containsCIS "\lsassdmp" OR TgtFilePath containsCIS "\lsassdump") OR (TgtFilePath containsCIS "\lsass" AND TgtFilePath containsCIS ".dmp") OR (TgtFilePath containsCIS "SQLDmpr" AND TgtFilePath endswithCIS ".mdmp") OR ((TgtFilePath containsCIS "\nanodump" OR TgtFilePath containsCIS "\proc_") AND TgtFilePath endswithCIS ".dmp")))

```