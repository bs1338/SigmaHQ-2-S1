# proc_creation_win_webshell_tool_recon

## Title
Webshell Tool Reconnaissance Activity

## ID
f64e5c19-879c-4bae-b471-6d84c8339677

## Author
Cian Heasley, Florian Roth (Nextron Systems)

## Date
2020-07-22

## Tags
attack.persistence, attack.t1505.003

## Description
Detects processes spawned from web servers (PHP, Tomcat, IIS, etc.) that perform reconnaissance looking for the existence of popular scripting tools (perl, python, wget) on the system via the help commands


## References
https://ragged-lab.blogspot.com/2020/07/webshells-automating-reconnaissance.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((SrcProcImagePath containsCIS "-tomcat-" OR SrcProcImagePath containsCIS "\tomcat") AND (SrcProcImagePath endswithCIS "\java.exe" OR SrcProcImagePath endswithCIS "\javaw.exe")) OR ((TgtProcCmdLine containsCIS "CATALINA_HOME" OR TgtProcCmdLine containsCIS "catalina.jar") AND (SrcProcImagePath endswithCIS "\java.exe" OR SrcProcImagePath endswithCIS "\javaw.exe")) OR (SrcProcImagePath endswithCIS "\caddy.exe" OR SrcProcImagePath endswithCIS "\httpd.exe" OR SrcProcImagePath endswithCIS "\nginx.exe" OR SrcProcImagePath endswithCIS "\php-cgi.exe" OR SrcProcImagePath endswithCIS "\w3wp.exe" OR SrcProcImagePath endswithCIS "\ws_tomcatservice.exe")) AND (TgtProcCmdLine containsCIS "perl --help" OR TgtProcCmdLine containsCIS "perl -h" OR TgtProcCmdLine containsCIS "python --help" OR TgtProcCmdLine containsCIS "python -h" OR TgtProcCmdLine containsCIS "python3 --help" OR TgtProcCmdLine containsCIS "python3 -h" OR TgtProcCmdLine containsCIS "wget --help")))

```