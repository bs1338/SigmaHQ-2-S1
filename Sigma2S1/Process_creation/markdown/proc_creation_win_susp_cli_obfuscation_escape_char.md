# proc_creation_win_susp_cli_obfuscation_escape_char

## Title
Potential Commandline Obfuscation Using Escape Characters

## ID
f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd

## Author
juju4

## Date
2018-12-11

## Tags
attack.defense-evasion, attack.t1140

## Description
Detects potential commandline obfuscation using known escape characters

## References
https://twitter.com/vysecurity/status/885545634958385153
https://twitter.com/Hexacorn/status/885553465417756673
https://twitter.com/Hexacorn/status/885570278637678592
https://www.mandiant.com/resources/blog/obfuscation-wild-targeted-attackers-lead-way-evasion-techniques
https://web.archive.org/web/20190213114956/http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "h^t^t^p" OR TgtProcCmdLine containsCIS "h\"t\"t\"p"))

```