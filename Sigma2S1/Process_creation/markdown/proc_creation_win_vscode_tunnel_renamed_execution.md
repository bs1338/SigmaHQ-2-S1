# proc_creation_win_vscode_tunnel_renamed_execution

## Title
Renamed Visual Studio Code Tunnel Execution

## ID
2cf29f11-e356-4f61-98c0-1bdb9393d6da

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-28

## Tags
attack.command-and-control, attack.t1071.001

## Description
Detects renamed Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel

## References
https://ipfyx.fr/post/visual-studio-code-tunnel/
https://badoption.eu/blog/2023/01/31/code_c2.html
https://code.visualstudio.com/docs/remote/tunnels

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcCmdLine containsCIS ".exe tunnel" AND TgtProcCmdLine containsCIS "--name " AND TgtProcCmdLine containsCIS "--accept-server-license-terms") OR (TgtProcCmdLine containsCIS "tunnel " AND TgtProcCmdLine containsCIS "service" AND TgtProcCmdLine containsCIS "internal-run" AND TgtProcCmdLine containsCIS "tunnel-service.log")) AND (NOT (TgtProcImagePath endswithCIS "\code-tunnel.exe" OR TgtProcImagePath endswithCIS "\code.exe"))) OR (((TgtProcCmdLine containsCIS "/d /c " AND TgtProcCmdLine containsCIS "\servers\Stable-" AND TgtProcCmdLine containsCIS "code-server.cmd") AND TgtProcImagePath endswithCIS "\cmd.exe" AND SrcProcCmdLine endswithCIS " tunnel") AND (NOT (SrcProcImagePath endswithCIS "\code-tunnel.exe" OR SrcProcImagePath endswithCIS "\code.exe")))))

```