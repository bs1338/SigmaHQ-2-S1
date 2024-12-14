# proc_creation_win_webshell_susp_process_spawned_from_webserver

## Title
Suspicious Process By Web Server Process

## ID
8202070f-edeb-4d31-a010-a26c72ac5600

## Author
Thomas Patzke, Florian Roth (Nextron Systems), Zach Stanford @svch0st, Tim Shelton, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-01-16

## Tags
attack.persistence, attack.t1505.003, attack.t1190

## Description
Detects potentially suspicious processes being spawned by a web server process which could be the result of a successfully placed web shell or exploitation


## References
https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF

## False Positives
Particular web applications may spawn a shell process legitimately

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((SrcProcImagePath containsCIS "-tomcat-" OR SrcProcImagePath containsCIS "\tomcat") AND (SrcProcImagePath endswithCIS "\java.exe" OR SrcProcImagePath endswithCIS "\javaw.exe")) OR ((SrcProcCmdLine containsCIS "CATALINA_HOME" OR SrcProcCmdLine containsCIS "catalina.home" OR SrcProcCmdLine containsCIS "catalina.jar") AND (SrcProcImagePath endswithCIS "\java.exe" OR SrcProcImagePath endswithCIS "\javaw.exe")) OR (SrcProcImagePath endswithCIS "\caddy.exe" OR SrcProcImagePath endswithCIS "\httpd.exe" OR SrcProcImagePath endswithCIS "\nginx.exe" OR SrcProcImagePath endswithCIS "\php-cgi.exe" OR SrcProcImagePath endswithCIS "\php.exe" OR SrcProcImagePath endswithCIS "\tomcat.exe" OR SrcProcImagePath endswithCIS "\UMWorkerProcess.exe" OR SrcProcImagePath endswithCIS "\w3wp.exe" OR SrcProcImagePath endswithCIS "\ws_TomcatService.exe")) AND (TgtProcImagePath endswithCIS "\arp.exe" OR TgtProcImagePath endswithCIS "\at.exe" OR TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\dsget.exe" OR TgtProcImagePath endswithCIS "\hostname.exe" OR TgtProcImagePath endswithCIS "\nbtstat.exe" OR TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe" OR TgtProcImagePath endswithCIS "\netdom.exe" OR TgtProcImagePath endswithCIS "\netsh.exe" OR TgtProcImagePath endswithCIS "\nltest.exe" OR TgtProcImagePath endswithCIS "\ntdsutil.exe" OR TgtProcImagePath endswithCIS "\powershell_ise.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\qprocess.exe" OR TgtProcImagePath endswithCIS "\query.exe" OR TgtProcImagePath endswithCIS "\qwinsta.exe" OR TgtProcImagePath endswithCIS "\reg.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\sc.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\wusa.exe") AND (NOT ((TgtProcCmdLine endswithCIS "Windows\system32\cmd.exe /c C:\ManageEngine\ADManager \"Plus\ES\bin\elasticsearch.bat -Enode.name=RMP-NODE1 -pelasticsearch-pid.txt" AND SrcProcImagePath endswithCIS "\java.exe") OR ((TgtProcCmdLine containsCIS "sc query" AND TgtProcCmdLine containsCIS "ADManager Plus") AND SrcProcImagePath endswithCIS "\java.exe")))))

```