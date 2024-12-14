# proc_creation_win_powershell_disable_ie_features

## Title
Disabled IE Security Features

## ID
fb50eb7a-5ab1-43ae-bcc9-091818cb8424

## Author
Florian Roth (Nextron Systems)

## Date
2020-06-19

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features

## References
https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -name IEHarden " AND TgtProcCmdLine containsCIS " -value 0 ") OR (TgtProcCmdLine containsCIS " -name DEPOff " AND TgtProcCmdLine containsCIS " -value 1 ") OR (TgtProcCmdLine containsCIS " -name DisableFirstRunCustomize " AND TgtProcCmdLine containsCIS " -value 2 ")))

```