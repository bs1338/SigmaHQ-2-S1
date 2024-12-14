# proc_creation_win_vscode_tunnel_service_install

## Title
Visual Studio Code Tunnel Service Installation

## ID
30bf1789-379d-4fdc-900f-55cd0a90a801

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-10-25

## Tags
attack.command-and-control, attack.t1071.001

## Description
Detects the installation of VsCode tunnel (code-tunnel) as a service.

## References
https://ipfyx.fr/post/visual-studio-code-tunnel/
https://badoption.eu/blog/2023/01/31/code_c2.html
https://code.visualstudio.com/docs/remote/tunnels

## False Positives
Legitimate installation of code-tunnel as a service

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "tunnel " AND TgtProcCmdLine containsCIS "service" AND TgtProcCmdLine containsCIS "internal-run" AND TgtProcCmdLine containsCIS "tunnel-service.log"))

```