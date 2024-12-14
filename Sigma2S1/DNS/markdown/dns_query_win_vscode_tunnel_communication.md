# dns_query_win_vscode_tunnel_communication

## Title
DNS Query To Visual Studio Code Tunnels Domain

## ID
b3e6418f-7c7a-4fad-993a-93b65027a9f1

## Author
citron_ninja

## Date
2023-10-25

## Tags
attack.command-and-control, attack.t1071.001

## Description
Detects DNS query requests to Visual Studio Code tunnel domains. Attackers can abuse that feature to establish a reverse shell or persistence on a machine.


## References
https://ipfyx.fr/post/visual-studio-code-tunnel/
https://badoption.eu/blog/2023/01/31/code_c2.html
https://cydefops.com/vscode-data-exfiltration

## False Positives
Legitimate use of Visual Studio Code tunnel will also trigger this.

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND DnsRequest endswithCIS ".tunnels.api.visualstudio.com")

```