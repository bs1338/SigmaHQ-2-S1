# proc_creation_win_reg_dumping_sensitive_hives

## Title
Dumping of Sensitive Hives Via Reg.EXE

## ID
fd877b94-9bb5-4191-bb25-d79cbd93c167

## Author
Teymur Kheirkhabarov, Endgame, JHasenbusch, Daniil Yugoslavskiy, oscd.community, frack113

## Date
2019-10-22

## Tags
attack.credential-access, attack.t1003.002, attack.t1003.004, attack.t1003.005, car.2013-07-001

## Description
Detects the usage of "reg.exe" in order to dump sensitive registry hives. This includes SAM, SYSTEM and SECURITY hives.

## References
https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
https://eqllib.readthedocs.io/en/latest/analytics/aed95fc6-5e3f-49dc-8b35-06508613f979.html
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003/T1003.md
https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md#atomic-test-1---registry-dump-of-sam-creds-and-secrets

## False Positives
Dumping hives for legitimate purpouse i.e. backup or forensic investigation

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " save " OR TgtProcCmdLine containsCIS " export " OR TgtProcCmdLine containsCIS " Ë¢ave " OR TgtProcCmdLine containsCIS " eË£port ") AND (TgtProcCmdLine containsCIS "\system" OR TgtProcCmdLine containsCIS "\sam" OR TgtProcCmdLine containsCIS "\security" OR TgtProcCmdLine containsCIS "\Ë¢ystem" OR TgtProcCmdLine containsCIS "\syË¢tem" OR TgtProcCmdLine containsCIS "\Ë¢yË¢tem" OR TgtProcCmdLine containsCIS "\Ë¢am" OR TgtProcCmdLine containsCIS "\Ë¢ecurity") AND (TgtProcCmdLine containsCIS "hklm" OR TgtProcCmdLine containsCIS "hkËªm" OR TgtProcCmdLine containsCIS "hkey_local_machine" OR TgtProcCmdLine containsCIS "hkey_Ëªocal_machine" OR TgtProcCmdLine containsCIS "hkey_locaËª_machine" OR TgtProcCmdLine containsCIS "hkey_ËªocaËª_machine") AND TgtProcImagePath endswithCIS "\reg.exe"))

```