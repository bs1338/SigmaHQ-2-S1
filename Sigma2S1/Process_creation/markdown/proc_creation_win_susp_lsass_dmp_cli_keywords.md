# proc_creation_win_susp_lsass_dmp_cli_keywords

## Title
LSASS Dump Keyword In CommandLine

## ID
ffa6861c-4461-4f59-8a41-578c39f3f23e

## Author
E.M. Anhaus, Tony Lambert, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-10-24

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects the presence of the keywords "lsass" and ".dmp" in the commandline, which could indicate a potential attempt to dump or create a dump of the lsass process.


## References
https://github.com/Hackndo/lsassy
https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf
https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/windows/credential_access_lsass_memdump_file_created.toml
https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/
https://github.com/helpsystems/nanodump
https://github.com/CCob/MirrorDump

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "lsass.dmp" OR TgtProcCmdLine containsCIS "lsass.zip" OR TgtProcCmdLine containsCIS "lsass.rar" OR TgtProcCmdLine containsCIS "Andrew.dmp" OR TgtProcCmdLine containsCIS "Coredump.dmp" OR TgtProcCmdLine containsCIS "NotLSASS.zip" OR TgtProcCmdLine containsCIS "lsass_2" OR TgtProcCmdLine containsCIS "lsassdump" OR TgtProcCmdLine containsCIS "lsassdmp") OR (TgtProcCmdLine containsCIS "lsass" AND TgtProcCmdLine containsCIS ".dmp") OR (TgtProcCmdLine containsCIS "SQLDmpr" AND TgtProcCmdLine containsCIS ".mdmp") OR (TgtProcCmdLine containsCIS "nanodump" AND TgtProcCmdLine containsCIS ".dmp")))

```