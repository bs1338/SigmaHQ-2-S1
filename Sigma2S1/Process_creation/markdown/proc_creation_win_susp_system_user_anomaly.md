# proc_creation_win_susp_system_user_anomaly

## Title
Suspicious SYSTEM User Process Creation

## ID
2617e7ed-adb7-40ba-b0f3-8f9945fe6c09

## Author
Florian Roth (Nextron Systems), David ANDRE (additional keywords)

## Date
2021-12-20

## Tags
attack.credential-access, attack.defense-evasion, attack.privilege-escalation, attack.t1134, attack.t1003, attack.t1027

## Description
Detects a suspicious process creation as SYSTEM user (suspicious program or command line parameter)

## References
Internal Research
https://tools.thehacker.recipes/mimikatz/modules

## False Positives
Administrative activity
Scripts and administrative tools used in the monitored environment
Monitoring activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcIntegrityLevel In ("System","S-1-16-16384")) AND (TgtProcUser containsCIS "AUTHORI" OR TgtProcUser containsCIS "AUTORI")) AND ((TgtProcImagePath endswithCIS "\calc.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\forfiles.exe" OR TgtProcImagePath endswithCIS "\hh.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\ping.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR (TgtProcCmdLine containsCIS " -NoP " OR TgtProcCmdLine containsCIS " -W Hidden " OR TgtProcCmdLine containsCIS " -decode " OR TgtProcCmdLine containsCIS " /decode " OR TgtProcCmdLine containsCIS " /urlcache " OR TgtProcCmdLine containsCIS " -urlcache " OR TgtProcCmdLine = "* -e* JAB*" OR TgtProcCmdLine = "* -e* SUVYI*" OR TgtProcCmdLine = "* -e* SQBFAFgA*" OR TgtProcCmdLine = "* -e* aWV4I*" OR TgtProcCmdLine = "* -e* IAB*" OR TgtProcCmdLine = "* -e* PAA*" OR TgtProcCmdLine = "* -e* aQBlAHgA*" OR TgtProcCmdLine containsCIS "vssadmin delete shadows" OR TgtProcCmdLine containsCIS "reg SAVE HKLM" OR TgtProcCmdLine containsCIS " -ma " OR TgtProcCmdLine containsCIS "Microsoft\Windows\CurrentVersion\Run" OR TgtProcCmdLine containsCIS ".downloadstring(" OR TgtProcCmdLine containsCIS ".downloadfile(" OR TgtProcCmdLine containsCIS " /ticket:" OR TgtProcCmdLine containsCIS "dpapi::" OR TgtProcCmdLine containsCIS "event::clear" OR TgtProcCmdLine containsCIS "event::drop" OR TgtProcCmdLine containsCIS "id::modify" OR TgtProcCmdLine containsCIS "kerberos::" OR TgtProcCmdLine containsCIS "lsadump::" OR TgtProcCmdLine containsCIS "misc::" OR TgtProcCmdLine containsCIS "privilege::" OR TgtProcCmdLine containsCIS "rpc::" OR TgtProcCmdLine containsCIS "sekurlsa::" OR TgtProcCmdLine containsCIS "sid::" OR TgtProcCmdLine containsCIS "token::" OR TgtProcCmdLine containsCIS "vault::cred" OR TgtProcCmdLine containsCIS "vault::list" OR TgtProcCmdLine containsCIS " p::d " OR TgtProcCmdLine containsCIS ";iex(" OR TgtProcCmdLine containsCIS "MiniDump" OR TgtProcCmdLine containsCIS "net user "))) AND (NOT (SrcProcImagePath containsCIS ":\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows\" OR (TgtProcCmdLine containsCIS " -ma " AND (TgtProcImagePath containsCIS ":\Program Files (x86)\Java\" OR TgtProcImagePath containsCIS ":\Program Files\Java\") AND TgtProcImagePath endswithCIS "\bin\jp2launcher.exe" AND (SrcProcImagePath containsCIS ":\Program Files (x86)\Java\" OR SrcProcImagePath containsCIS ":\Program Files\Java\") AND SrcProcImagePath endswithCIS "\bin\javaws.exe") OR (TgtProcCmdLine containsCIS "ping" AND TgtProcCmdLine containsCIS "127.0.0.1" AND TgtProcCmdLine containsCIS " -n ") OR (TgtProcImagePath endswithCIS "\PING.EXE" AND SrcProcCmdLine containsCIS "\DismFoDInstall.cmd")))))

```