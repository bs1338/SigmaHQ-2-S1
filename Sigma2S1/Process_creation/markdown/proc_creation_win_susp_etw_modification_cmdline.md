# proc_creation_win_susp_etw_modification_cmdline

## Title
ETW Logging Tamper In .NET Processes Via CommandLine

## ID
41421f44-58f9-455d-838a-c398859841d4

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2020-05-02

## Tags
attack.defense-evasion, attack.t1562

## Description
Detects changes to environment variables related to ETW logging via the CommandLine.
This could indicate potential adversaries stopping ETW providers recording loaded .NET assemblies.


## References
https://twitter.com/_xpn_/status/1268712093928378368
https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr
https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables
https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38
https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39
https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_
https://bunnyinside.com/?term=f71e8cb9c76a
http://managed670.rssing.com/chan-5590147/all_p1.html
https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code
https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "COMPlus_ETWEnabled" OR TgtProcCmdLine containsCIS "COMPlus_ETWFlags"))

```