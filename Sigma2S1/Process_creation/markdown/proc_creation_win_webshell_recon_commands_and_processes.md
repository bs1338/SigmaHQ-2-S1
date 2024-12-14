# proc_creation_win_webshell_recon_commands_and_processes

## Title
Webshell Detection With Command Line Keywords

## ID
bed2a484-9348-4143-8a8a-b801c979301c

## Author
Florian Roth (Nextron Systems), Jonhnathan Ribeiro, Anton Kutepov, oscd.community

## Date
2017-01-01

## Tags
attack.persistence, attack.t1505.003, attack.t1018, attack.t1033, attack.t1087

## Description
Detects certain command line parameters often used during reconnaissance activity via web shells

## References
https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html
https://unit42.paloaltonetworks.com/bumblebee-webshell-xhunt-campaign/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((SrcProcImagePath containsCIS "-tomcat-" OR SrcProcImagePath containsCIS "\tomcat") AND (SrcProcImagePath endswithCIS "\java.exe" OR SrcProcImagePath endswithCIS "\javaw.exe")) OR ((TgtProcCmdLine containsCIS "catalina.jar" OR TgtProcCmdLine containsCIS "CATALINA_HOME") AND (SrcProcImagePath endswithCIS "\java.exe" OR SrcProcImagePath endswithCIS "\javaw.exe")) OR (SrcProcImagePath endswithCIS "\w3wp.exe" OR SrcProcImagePath endswithCIS "\php-cgi.exe" OR SrcProcImagePath endswithCIS "\nginx.exe" OR SrcProcImagePath endswithCIS "\httpd.exe" OR SrcProcImagePath endswithCIS "\caddy.exe" OR SrcProcImagePath endswithCIS "\ws_tomcatservice.exe")) AND ((TgtProcCmdLine containsCIS "&cd&echo" OR TgtProcCmdLine containsCIS "cd /d ") OR (TgtProcImagePath endswithCIS "\dsquery.exe" OR TgtProcImagePath endswithCIS "\find.exe" OR TgtProcImagePath endswithCIS "\findstr.exe" OR TgtProcImagePath endswithCIS "\ipconfig.exe" OR TgtProcImagePath endswithCIS "\netstat.exe" OR TgtProcImagePath endswithCIS "\nslookup.exe" OR TgtProcImagePath endswithCIS "\pathping.exe" OR TgtProcImagePath endswithCIS "\quser.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\systeminfo.exe" OR TgtProcImagePath endswithCIS "\tasklist.exe" OR TgtProcImagePath endswithCIS "\tracert.exe" OR TgtProcImagePath endswithCIS "\ver.exe" OR TgtProcImagePath endswithCIS "\wevtutil.exe" OR TgtProcImagePath endswithCIS "\whoami.exe") OR (TgtProcCmdLine containsCIS " Test-NetConnection " OR TgtProcCmdLine containsCIS "dir \"))))

```