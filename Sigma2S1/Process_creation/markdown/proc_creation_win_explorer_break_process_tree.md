# proc_creation_win_explorer_break_process_tree

## Title
Explorer Process Tree Break

## ID
949f1ffb-6e85-4f00-ae1e-c3c5b190d605

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems), @gott_cyber

## Date
2019-06-29

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects a command line process that uses explorer.exe to launch arbitrary commands or binaries,
which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer spawning from "svchost"


## References
https://twitter.com/CyberRaiju/status/1273597319322058752
https://twitter.com/bohops/status/1276357235954909188?s=12
https://twitter.com/nas_bench/status/1535322450858233858
https://securityboulevard.com/2019/09/deobfuscating-ostap-trickbots-34000-line-javascript-downloader/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}" OR ((TgtProcCmdLine containsCIS "explorer.exe") AND (TgtProcCmdLine containsCIS " -root," OR TgtProcCmdLine containsCIS " /root," OR TgtProcCmdLine containsCIS " â€“root," OR TgtProcCmdLine containsCIS " â€”root," OR TgtProcCmdLine containsCIS " â€•root,"))))

```