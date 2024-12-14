# proc_creation_win_rundll32_mshtml_runhtmlapplication

## Title
Mshtml.DLL RunHTMLApplication Suspicious Usage

## ID
4782eb5a-a513-4523-a0ac-f3082b26ac5c

## Author
Nasreddine Bencherchali (Nextron Systems),  Florian Roth (Nextron Systems), Josh Nickels, frack113, Zaw Min Htun (ZETA)

## Date
2022-08-14

## Tags
attack.defense-evasion, attack.execution

## Description
Detects execution of commands that leverage the "mshtml.dll" RunHTMLApplication export to run arbitrary code via different protocol handlers (vbscript, javascript, file, http...)


## References
https://twitter.com/n1nj4sec/status/1421190238081277959
https://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_TROJAN.WIN32.POWESSERE.G_MITIGATION_BYPASS_PART2.txt
http://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_DETECTION_BYPASS.txt

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "#135" OR TgtProcCmdLine containsCIS "RunHTMLApplication") AND (TgtProcCmdLine containsCIS "\..\" AND TgtProcCmdLine containsCIS "mshtml")))

```