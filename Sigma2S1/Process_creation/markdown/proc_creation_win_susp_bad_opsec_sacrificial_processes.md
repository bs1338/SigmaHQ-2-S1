# proc_creation_win_susp_bad_opsec_sacrificial_processes

## Title
Bad Opsec Defaults Sacrificial Processes With Improper Arguments

## ID
a7c3d773-caef-227e-a7e7-c2f13c622329

## Author
Oleg Kolesnikov @securonix invrep_de, oscd.community, Florian Roth (Nextron Systems), Christian Burkard (Nextron Systems)

## Date
2020-10-23

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects attackers using tooling with bad opsec defaults.
E.g. spawning a sacrificial process to inject a capability into the process without taking into account how the process is normally run.
One trivial example of this is using rundll32.exe without arguments as a sacrificial process (default in CS, now highlighted by c2lint), running WerFault without arguments (Kraken - credit am0nsec), and other examples.


## References
https://blog.malwarebytes.com/malwarebytes-news/2020/10/kraken-attack-abuses-wer-service/
https://www.cobaltstrike.com/help-opsec
https://twitter.com/CyberRaiju/status/1251492025678983169
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32
https://learn.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool
https://learn.microsoft.com/en-us/dotnet/framework/tools/regsvcs-exe-net-services-installation-tool

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine endswithCIS "regasm.exe" AND TgtProcImagePath endswithCIS "\regasm.exe") OR (TgtProcCmdLine endswithCIS "regsvcs.exe" AND TgtProcImagePath endswithCIS "\regsvcs.exe") OR (TgtProcCmdLine endswithCIS "regsvr32.exe" AND TgtProcImagePath endswithCIS "\regsvr32.exe") OR (TgtProcCmdLine endswithCIS "rundll32.exe" AND TgtProcImagePath endswithCIS "\rundll32.exe") OR (TgtProcCmdLine endswithCIS "WerFault.exe" AND TgtProcImagePath endswithCIS "\WerFault.exe")) AND (NOT ((TgtProcCmdLine endswithCIS "rundll32.exe" AND TgtProcImagePath endswithCIS "\rundll32.exe" AND SrcProcCmdLine containsCIS "--uninstall " AND (SrcProcImagePath containsCIS "\AppData\Local\BraveSoftware\Brave-Browser\Application\" OR SrcProcImagePath containsCIS "\AppData\Local\Google\Chrome\Application\") AND SrcProcImagePath endswithCIS "\Installer\setup.exe") OR (TgtProcCmdLine endswithCIS "rundll32.exe" AND TgtProcImagePath endswithCIS "\rundll32.exe" AND SrcProcImagePath containsCIS "\AppData\Local\Microsoft\EdgeUpdate\Install\{")))))

```