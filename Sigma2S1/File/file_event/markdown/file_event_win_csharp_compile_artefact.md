# file_event_win_csharp_compile_artefact

## Title
Dynamic CSharp Compile Artefact

## ID
e4a74e34-ecde-4aab-b2fb-9112dd01aed0

## Author
frack113

## Date
2022-01-09

## Tags
attack.defense-evasion, attack.t1027.004

## Description
When C# is compiled dynamically, a .cmdline file will be created as a part of the process.
Certain processes are not typically observed compiling C# code, but can do so without touching disk.
This can be used to unpack a payload for execution


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027.004/T1027.004.md#atomic-test-2---dynamic-c-compile

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS ".cmdline")

```