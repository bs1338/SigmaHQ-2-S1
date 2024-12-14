# proc_creation_win_susp_copy_browser_data

## Title
Potential Browser Data Stealing

## ID
47147b5b-9e17-4d76-b8d2-7bac24c5ce1b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-23

## Tags
attack.credential-access, attack.t1555.003

## Description
Adversaries may acquire credentials from web browsers by reading files specific to the target browser.
Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future.
Web browsers typically store the credentials in an encrypted format within a credential store.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555.003/T1555.003.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "copy-item" OR TgtProcCmdLine containsCIS "copy " OR TgtProcCmdLine containsCIS "cpi " OR TgtProcCmdLine containsCIS " cp " OR TgtProcCmdLine containsCIS "move " OR TgtProcCmdLine containsCIS "move-item" OR TgtProcCmdLine containsCIS " mi " OR TgtProcCmdLine containsCIS " mv ") OR (TgtProcImagePath endswithCIS "\xcopy.exe" OR TgtProcImagePath endswithCIS "\robocopy.exe")) AND (TgtProcCmdLine containsCIS "\Amigo\User Data" OR TgtProcCmdLine containsCIS "\BraveSoftware\Brave-Browser\User Data" OR TgtProcCmdLine containsCIS "\CentBrowser\User Data" OR TgtProcCmdLine containsCIS "\Chromium\User Data" OR TgtProcCmdLine containsCIS "\CocCoc\Browser\User Data" OR TgtProcCmdLine containsCIS "\Comodo\Dragon\User Data" OR TgtProcCmdLine containsCIS "\Elements Browser\User Data" OR TgtProcCmdLine containsCIS "\Epic Privacy Browser\User Data" OR TgtProcCmdLine containsCIS "\Google\Chrome Beta\User Data" OR TgtProcCmdLine containsCIS "\Google\Chrome SxS\User Data" OR TgtProcCmdLine containsCIS "\Google\Chrome\User Data\" OR TgtProcCmdLine containsCIS "\Kometa\User Data" OR TgtProcCmdLine containsCIS "\Maxthon5\Users" OR TgtProcCmdLine containsCIS "\Microsoft\Edge\User Data" OR TgtProcCmdLine containsCIS "\Mozilla\Firefox\Profiles" OR TgtProcCmdLine containsCIS "\Nichrome\User Data" OR TgtProcCmdLine containsCIS "\Opera Software\Opera GX Stable\" OR TgtProcCmdLine containsCIS "\Opera Software\Opera Neon\User Data" OR TgtProcCmdLine containsCIS "\Opera Software\Opera Stable\" OR TgtProcCmdLine containsCIS "\Orbitum\User Data" OR TgtProcCmdLine containsCIS "\QIP Surf\User Data" OR TgtProcCmdLine containsCIS "\Sputnik\User Data" OR TgtProcCmdLine containsCIS "\Torch\User Data" OR TgtProcCmdLine containsCIS "\uCozMedia\Uran\User Data" OR TgtProcCmdLine containsCIS "\Vivaldi\User Data")))

```