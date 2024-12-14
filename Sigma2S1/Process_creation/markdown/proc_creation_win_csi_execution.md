# proc_creation_win_csi_execution

## Title
Suspicious Csi.exe Usage

## ID
40b95d31-1afc-469e-8d34-9a3a667d058e

## Author
Konstantin Grishchenko, oscd.community

## Date
2020-10-17

## Tags
attack.execution, attack.t1072, attack.defense-evasion, attack.t1218

## Description
Csi.exe is a signed binary from Microsoft that comes with Visual Studio and provides C# interactive capabilities. It can be used to run C# code from a file passed as a parameter in command line. Early version of this utility provided with Microsoft “Roslyn” Community Technology Preview was named 'rcsi.exe'

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Csi/
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Rcsi/
https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/
https://twitter.com/Z3Jpa29z/status/1317545798981324801

## False Positives
Legitimate usage by software developers

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcPublisher = "Microsoft Corporation" AND (TgtProcImagePath endswithCIS "\csi.exe" OR TgtProcImagePath endswithCIS "\rcsi.exe")))

```