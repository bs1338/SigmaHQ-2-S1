# proc_creation_win_cmdl32_arbitrary_file_download

## Title
Potential Arbitrary File Download Via Cmdl32.EXE

## ID
f37aba28-a9e6-4045-882c-d5004043b337

## Author
frack113

## Date
2021-11-03

## Tags
attack.execution, attack.defense-evasion, attack.t1218, attack.t1202

## Description
Detects execution of Cmdl32 with the "/vpn" and "/lan" flags.
 Attackers can abuse this utility in order to download arbitrary files via a configuration file.
Inspect the location and the content of the file passed as an argument in order to determine if it is suspicious.


## References
https://lolbas-project.github.io/lolbas/Binaries/Cmdl32/
https://twitter.com/SwiftOnSecurity/status/1455897435063074824
https://github.com/LOLBAS-Project/LOLBAS/pull/151

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/vpn" AND TgtProcCmdLine containsCIS "/lan") AND TgtProcImagePath endswithCIS "\cmdl32.exe"))

```