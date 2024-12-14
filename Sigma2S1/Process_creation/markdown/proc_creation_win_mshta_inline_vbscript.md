# proc_creation_win_mshta_inline_vbscript

## Title
Wscript Shell Run In CommandLine

## ID
2c28c248-7f50-417a-9186-a85b223010ee

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-31

## Tags
attack.execution, attack.t1059

## Description
Detects the presence of the keywords "Wscript", "Shell" and "Run" in the command, which could indicate a suspicious activity

## References
https://web.archive.org/web/20220830122045/http://blog.talosintelligence.com/2022/08/modernloader-delivers-multiple-stealers.html
https://blog.talosintelligence.com/modernloader-delivers-multiple-stealers-cryptominers-and-rats/

## False Positives
Inline scripting can be used by some rare third party applications or administrators. Investigate and apply additional filters accordingly

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Wscript." AND TgtProcCmdLine containsCIS ".Shell" AND TgtProcCmdLine containsCIS ".Run"))

```