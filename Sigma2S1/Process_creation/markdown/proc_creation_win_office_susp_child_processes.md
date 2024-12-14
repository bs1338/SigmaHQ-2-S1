# proc_creation_win_office_susp_child_processes

## Title
Suspicious Microsoft Office Child Process

## ID
438025f9-5856-4663-83f7-52f878a70a50

## Author
Florian Roth (Nextron Systems), Markus Neis, FPT.EagleEye Team, Vadim Khrykov, Cyb3rEng, Michael Haag, Christopher Peacock @securepeacock, @scythe_io

## Date
2018-04-06

## Tags
attack.defense-evasion, attack.execution, attack.t1047, attack.t1204.002, attack.t1218.010

## Description
Detects a suspicious process spawning from one of the Microsoft Office suite products (Word, Excel, PowerPoint, Publisher, Visio, etc.)

## References
https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100
https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e
https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/02bcbfc2bfb8b4da601bb30de0344ae453aa1afe/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml
https://github.com/splunk/security_content/blob/develop/detections/endpoint/office_spawning_control.yml
https://twitter.com/andythevariable/status/1576953781581144064?s=20&t=QiJILvK4ZiBdR8RJe24u-A
https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set
https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/windows/defense_evasion_execution_msbuild_started_by_office_app.toml
https://www.vmray.com/analyses/2d2fa29185ad/report/overview.html
https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\EQNEDT32.EXE" OR SrcProcImagePath endswithCIS "\EXCEL.EXE" OR SrcProcImagePath endswithCIS "\MSACCESS.EXE" OR SrcProcImagePath endswithCIS "\MSPUB.exe" OR SrcProcImagePath endswithCIS "\ONENOTE.EXE" OR SrcProcImagePath endswithCIS "\POWERPNT.exe" OR SrcProcImagePath endswithCIS "\VISIO.exe" OR SrcProcImagePath endswithCIS "\WINWORD.EXE" OR SrcProcImagePath endswithCIS "\wordpad.exe" OR SrcProcImagePath endswithCIS "\wordview.exe") AND ((TgtProcImagePath endswithCIS "\AppVLP.exe" OR TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\certoc.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cmstp.exe" OR TgtProcImagePath endswithCIS "\control.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\curl.exe" OR TgtProcImagePath endswithCIS "\forfiles.exe" OR TgtProcImagePath endswithCIS "\hh.exe" OR TgtProcImagePath endswithCIS "\ieexec.exe" OR TgtProcImagePath endswithCIS "\installutil.exe" OR TgtProcImagePath endswithCIS "\javaw.exe" OR TgtProcImagePath endswithCIS "\mftrace.exe" OR TgtProcImagePath endswithCIS "\Microsoft.Workflow.Compiler.exe" OR TgtProcImagePath endswithCIS "\msbuild.exe" OR TgtProcImagePath endswithCIS "\msdt.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\msidb.exe" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\msxsl.exe" OR TgtProcImagePath endswithCIS "\odbcconf.exe" OR TgtProcImagePath endswithCIS "\pcalua.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regasm.exe" OR TgtProcImagePath endswithCIS "\regsvcs.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\scrcons.exe" OR TgtProcImagePath endswithCIS "\scriptrunner.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\svchost.exe" OR TgtProcImagePath endswithCIS "\verclsid.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\workfolders.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR (TgtProcImagePath containsCIS "\AppData\" OR TgtProcImagePath containsCIS "\Users\Public\" OR TgtProcImagePath containsCIS "\ProgramData\" OR TgtProcImagePath containsCIS "\Windows\Tasks\" OR TgtProcImagePath containsCIS "\Windows\Temp\" OR TgtProcImagePath containsCIS "\Windows\System32\Tasks\"))))

```