# proc_creation_win_pua_chisel

## Title
PUA - Chisel Tunneling Tool Execution

## ID
8b0e12da-d3c3-49db-bb4f-256703f380e5

## Author
Florian Roth (Nextron Systems)

## Date
2022-09-13

## Tags
attack.command-and-control, attack.t1090.001

## Description
Detects usage of the Chisel tunneling tool via the commandline arguments

## References
https://github.com/jpillora/chisel/
https://arcticwolf.com/resources/blog/lorenz-ransomware-chiseling-in/
https://blog.sekoia.io/lucky-mouse-incident-response-to-detection-engineering/

## False Positives
Some false positives may occur with other tools with similar commandlines

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\chisel.exe" OR ((TgtProcCmdLine containsCIS "exe client " OR TgtProcCmdLine containsCIS "exe server ") AND (TgtProcCmdLine containsCIS "-socks5" OR TgtProcCmdLine containsCIS "-reverse" OR TgtProcCmdLine containsCIS " r:" OR TgtProcCmdLine containsCIS ":127.0.0.1:" OR TgtProcCmdLine containsCIS "-tls-skip-verify " OR TgtProcCmdLine containsCIS ":socks"))))

```