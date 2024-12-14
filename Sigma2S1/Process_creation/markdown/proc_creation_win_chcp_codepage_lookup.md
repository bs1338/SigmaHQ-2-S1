# proc_creation_win_chcp_codepage_lookup

## Title
Console CodePage Lookup Via CHCP

## ID
7090adee-82e2-4269-bd59-80691e7c6338

## Author
_pete_0, TheDFIRReport

## Date
2022-02-21

## Tags
attack.discovery, attack.t1614.001

## Description
Detects use of chcp to look up the system locale value as part of host discovery

## References
https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chcp

## False Positives
During Anaconda update the 'conda.exe' process will eventually execution the 'chcp' command.
Discord was seen using chcp to look up code pages

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS "chcp" OR TgtProcCmdLine endswithCIS "chcp " OR TgtProcCmdLine endswithCIS "chcp  ") AND TgtProcImagePath endswithCIS "\chcp.com" AND (SrcProcCmdLine containsCIS " -c " OR SrcProcCmdLine containsCIS " /c " OR SrcProcCmdLine containsCIS " â€“c " OR SrcProcCmdLine containsCIS " â€”c " OR SrcProcCmdLine containsCIS " â€•c " OR SrcProcCmdLine containsCIS " -r " OR SrcProcCmdLine containsCIS " /r " OR SrcProcCmdLine containsCIS " â€“r " OR SrcProcCmdLine containsCIS " â€”r " OR SrcProcCmdLine containsCIS " â€•r " OR SrcProcCmdLine containsCIS " -k " OR SrcProcCmdLine containsCIS " /k " OR SrcProcCmdLine containsCIS " â€“k " OR SrcProcCmdLine containsCIS " â€”k " OR SrcProcCmdLine containsCIS " â€•k ") AND SrcProcImagePath endswithCIS "\cmd.exe"))

```