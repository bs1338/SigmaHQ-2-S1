# proc_creation_win_powershell_base64_reflection_assembly_load_obfusc

## Title
Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call

## ID
9c0295ce-d60d-40bd-bd74-84673b7592b1

## Author
pH-T (Nextron Systems)

## Date
2022-03-01

## Tags
attack.execution, attack.defense-evasion, attack.t1059.001, attack.t1027

## Description
Detects suspicious base64 encoded and obfuscated "LOAD" keyword used in .NET "reflection.assembly"

## References
https://github.com/Neo23x0/Raccine/blob/20a569fa21625086433dcce8bb2765d0ea08dcb6/yara/mal_revil.yar
https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
https://learn.microsoft.com/en-us/dotnet/api/system.appdomain.load?view=net-7.0

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ" OR TgtProcCmdLine containsCIS "oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA" OR TgtProcCmdLine containsCIS "6ADoAKAAiAEwAIgArACIAbwBhAGQAIgApA" OR TgtProcCmdLine containsCIS "OgA6ACgAIgBMAG8AIgArACIAYQBkACIAKQ" OR TgtProcCmdLine containsCIS "oAOgAoACIATABvACIAKwAiAGEAZAAiACkA" OR TgtProcCmdLine containsCIS "6ADoAKAAiAEwAbwAiACsAIgBhAGQAIgApA" OR TgtProcCmdLine containsCIS "OgA6ACgAIgBMAG8AYQAiACsAIgBkACIAKQ" OR TgtProcCmdLine containsCIS "oAOgAoACIATABvAGEAIgArACIAZAAiACkA" OR TgtProcCmdLine containsCIS "6ADoAKAAiAEwAbwBhACIAKwAiAGQAIgApA" OR TgtProcCmdLine containsCIS "OgA6ACgAJwBMACcAKwAnAG8AYQBkACcAKQ" OR TgtProcCmdLine containsCIS "oAOgAoACcATAAnACsAJwBvAGEAZAAnACkA" OR TgtProcCmdLine containsCIS "6ADoAKAAnAEwAJwArACcAbwBhAGQAJwApA" OR TgtProcCmdLine containsCIS "OgA6ACgAJwBMAG8AJwArACcAYQBkACcAKQ" OR TgtProcCmdLine containsCIS "oAOgAoACcATABvACcAKwAnAGEAZAAnACkA" OR TgtProcCmdLine containsCIS "6ADoAKAAnAEwAbwAnACsAJwBhAGQAJwApA" OR TgtProcCmdLine containsCIS "OgA6ACgAJwBMAG8AYQAnACsAJwBkACcAKQ" OR TgtProcCmdLine containsCIS "oAOgAoACcATABvAGEAJwArACcAZAAnACkA" OR TgtProcCmdLine containsCIS "6ADoAKAAnAEwAbwBhACcAKwAnAGQAJwApA"))

```