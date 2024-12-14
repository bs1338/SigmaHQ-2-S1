# proc_creation_win_vscode_tunnel_execution

## Title
Visual Studio Code Tunnel Execution

## ID
90d6bd71-dffb-4989-8d86-a827fedd6624

## Author
Nasreddine Bencherchali (Nextron Systems), citron_ninja

## Date
2023-10-25

## Tags
attack.command-and-control, attack.t1071.001

## Description
Detects Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel

## References
https://ipfyx.fr/post/visual-studio-code-tunnel/
https://badoption.eu/blog/2023/01/31/code_c2.html
https://code.visualstudio.com/docs/remote/tunnels

## False Positives
Legitimate use of Visual Studio Code tunnel

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "/d /c " AND TgtProcCmdLine containsCIS "\servers\Stable-" AND TgtProcCmdLine containsCIS "code-server.cmd") AND TgtProcImagePath endswithCIS "\cmd.exe" AND SrcProcCmdLine endswithCIS " tunnel") OR (TgtProcCmdLine containsCIS ".exe tunnel" AND TgtProcCmdLine containsCIS "--name " AND TgtProcCmdLine containsCIS "--accept-server-license-terms")))

```