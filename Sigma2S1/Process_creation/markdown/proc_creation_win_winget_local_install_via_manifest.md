# proc_creation_win_winget_local_install_via_manifest

## Title
Install New Package Via Winget Local Manifest

## ID
313d6012-51a0-4d93-8dfc-de8553239e25

## Author
Sreeman, Florian Roth (Nextron Systems), frack113

## Date
2020-04-21

## Tags
attack.defense-evasion, attack.execution, attack.t1059

## Description
Detects usage of winget to install applications via manifest file. Adversaries can abuse winget to download payloads remotely and execute them.
The manifest option enables you to install an application by passing in a YAML file directly to the client.
Winget can be used to download and install exe, msi or msix files later.


## References
https://learn.microsoft.com/en-us/windows/package-manager/winget/install#local-install
https://lolbas-project.github.io/lolbas/Binaries/Winget/
https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget

## False Positives
Some false positives are expected in some environment that may use this functionality to install and test their custom applications

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\winget.exe" AND (TgtProcCmdLine containsCIS "install" OR TgtProcCmdLine containsCIS " add ") AND (TgtProcCmdLine containsCIS "-m " OR TgtProcCmdLine containsCIS "--manifest")))

```