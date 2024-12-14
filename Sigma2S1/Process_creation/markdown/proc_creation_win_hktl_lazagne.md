# proc_creation_win_hktl_lazagne

## Title
HackTool - LaZagne Execution

## ID
c2b86e67-b880-4eec-b045-50bc98ef4844

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-06-24

## Tags
attack.credential-access

## Description
Detects the execution of the LaZagne. A utility used to retrieve multiple types of passwords stored on a local computer.
LaZagne has been leveraged multiple times by threat actors in order to dump credentials.


## References
https://github.com/AlessandroZ/LaZagne/tree/master
https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
https://cloud.google.com/blog/topics/threat-intelligence/alphv-ransomware-backup/
https://securelist.com/defttorero-tactics-techniques-and-procedures/107610/
https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/raw/800c0e06571993a54e39571cf27fd474dcc5c0bc/2017/2017.11.14.Muddying_the_Water/muddying-the-water-targeted-attacks.pdf

## False Positives
Some false positive is expected from tools with similar command line flags.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\lazagne.exe" OR ((TgtProcCmdLine endswithCIS ".exe all" OR TgtProcCmdLine endswithCIS ".exe browsers" OR TgtProcCmdLine endswithCIS ".exe chats" OR TgtProcCmdLine endswithCIS ".exe databases" OR TgtProcCmdLine endswithCIS ".exe games" OR TgtProcCmdLine endswithCIS ".exe git" OR TgtProcCmdLine endswithCIS ".exe mails" OR TgtProcCmdLine endswithCIS ".exe maven" OR TgtProcCmdLine endswithCIS ".exe memory" OR TgtProcCmdLine endswithCIS ".exe multimedia" OR TgtProcCmdLine endswithCIS ".exe sysadmin" OR TgtProcCmdLine endswithCIS ".exe unused" OR TgtProcCmdLine endswithCIS ".exe wifi" OR TgtProcCmdLine endswithCIS ".exe windows") AND (TgtProcImagePath containsCIS ":\PerfLogs\" OR TgtProcImagePath containsCIS ":\ProgramData\" OR TgtProcImagePath containsCIS ":\Temp\" OR TgtProcImagePath containsCIS ":\Tmp\" OR TgtProcImagePath containsCIS ":\Windows\Temp\" OR TgtProcImagePath containsCIS "\AppData\" OR TgtProcImagePath containsCIS "\Downloads\" OR TgtProcImagePath containsCIS "\Users\Public\")) OR ((TgtProcCmdLine containsCIS "all " OR TgtProcCmdLine containsCIS "browsers " OR TgtProcCmdLine containsCIS "chats " OR TgtProcCmdLine containsCIS "databases " OR TgtProcCmdLine containsCIS "games " OR TgtProcCmdLine containsCIS "git " OR TgtProcCmdLine containsCIS "mails " OR TgtProcCmdLine containsCIS "maven " OR TgtProcCmdLine containsCIS "memory " OR TgtProcCmdLine containsCIS "multimedia " OR TgtProcCmdLine containsCIS "php " OR TgtProcCmdLine containsCIS "svn " OR TgtProcCmdLine containsCIS "sysadmin " OR TgtProcCmdLine containsCIS "unused " OR TgtProcCmdLine containsCIS "wifi " OR TgtProcCmdLine containsCIS "windows ") AND (TgtProcCmdLine containsCIS "-oA" OR TgtProcCmdLine containsCIS "-oJ" OR TgtProcCmdLine containsCIS "-oN" OR TgtProcCmdLine containsCIS "-output" OR TgtProcCmdLine containsCIS "-password" OR TgtProcCmdLine containsCIS "-1Password" OR TgtProcCmdLine containsCIS "-apachedirectorystudio" OR TgtProcCmdLine containsCIS "-autologon" OR TgtProcCmdLine containsCIS "-ChromiumBased" OR TgtProcCmdLine containsCIS "-composer" OR TgtProcCmdLine containsCIS "-coreftp" OR TgtProcCmdLine containsCIS "-credfiles" OR TgtProcCmdLine containsCIS "-credman" OR TgtProcCmdLine containsCIS "-cyberduck" OR TgtProcCmdLine containsCIS "-dbvis" OR TgtProcCmdLine containsCIS "-EyeCon" OR TgtProcCmdLine containsCIS "-filezilla" OR TgtProcCmdLine containsCIS "-filezillaserver" OR TgtProcCmdLine containsCIS "-ftpnavigator" OR TgtProcCmdLine containsCIS "-galconfusion" OR TgtProcCmdLine containsCIS "-gitforwindows" OR TgtProcCmdLine containsCIS "-hashdump" OR TgtProcCmdLine containsCIS "-iisapppool" OR TgtProcCmdLine containsCIS "-IISCentralCertP" OR TgtProcCmdLine containsCIS "-kalypsomedia" OR TgtProcCmdLine containsCIS "-keepass" OR TgtProcCmdLine containsCIS "-keepassconfig" OR TgtProcCmdLine containsCIS "-lsa_secrets" OR TgtProcCmdLine containsCIS "-mavenrepositories" OR TgtProcCmdLine containsCIS "-memory_dump" OR TgtProcCmdLine containsCIS "-Mozilla" OR TgtProcCmdLine containsCIS "-mRemoteNG" OR TgtProcCmdLine containsCIS "-mscache" OR TgtProcCmdLine containsCIS "-opensshforwindows" OR TgtProcCmdLine containsCIS "-openvpn" OR TgtProcCmdLine containsCIS "-outlook" OR TgtProcCmdLine containsCIS "-pidgin" OR TgtProcCmdLine containsCIS "-postgresql" OR TgtProcCmdLine containsCIS "-psi-im" OR TgtProcCmdLine containsCIS "-puttycm" OR TgtProcCmdLine containsCIS "-pypykatz" OR TgtProcCmdLine containsCIS "-Rclone" OR TgtProcCmdLine containsCIS "-rdpmanager" OR TgtProcCmdLine containsCIS "-robomongo" OR TgtProcCmdLine containsCIS "-roguestale" OR TgtProcCmdLine containsCIS "-skype" OR TgtProcCmdLine containsCIS "-SQLDeveloper" OR TgtProcCmdLine containsCIS "-squirrel" OR TgtProcCmdLine containsCIS "-tortoise" OR TgtProcCmdLine containsCIS "-turba" OR TgtProcCmdLine containsCIS "-UCBrowser" OR TgtProcCmdLine containsCIS "-unattended" OR TgtProcCmdLine containsCIS "-vault" OR TgtProcCmdLine containsCIS "-vaultfiles" OR TgtProcCmdLine containsCIS "-vnc" OR TgtProcCmdLine containsCIS "-windows" OR TgtProcCmdLine containsCIS "-winscp" OR TgtProcCmdLine containsCIS "-wsl"))))

```