# proc_creation_win_pua_adfind_susp_usage

## Title
PUA - AdFind Suspicious Execution

## ID
9a132afa-654e-11eb-ae93-0242ac130002

## Author
Janantha Marasinghe (https://github.com/blueteam0ps), FPT.EagleEye Team, omkar72, oscd.community

## Date
2021-02-02

## Tags
attack.discovery, attack.t1018, attack.t1087.002, attack.t1482, attack.t1069.002, stp.1u

## Description
Detects AdFind execution with common flags seen used during attacks

## References
https://www.joeware.net/freetools/tools/adfind/
https://thedfirreport.com/2020/05/08/adfind-recon/
https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/
https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/bf62ece1c679b07b5fb49c4bae947fe24c81811f/fin6/Emulation_Plan/Phase1.md
https://github.com/redcanaryco/atomic-red-team/blob/0f229c0e42bfe7ca736a14023836d65baa941ed2/atomics/T1087.002/T1087.002.md#atomic-test-7---adfind---enumerate-active-directory-user-objects

## False Positives
Legitimate admin activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "domainlist" OR TgtProcCmdLine containsCIS "trustdmp" OR TgtProcCmdLine containsCIS "dcmodes" OR TgtProcCmdLine containsCIS "adinfo" OR TgtProcCmdLine containsCIS " dclist " OR TgtProcCmdLine containsCIS "computer_pwdnotreqd" OR TgtProcCmdLine containsCIS "objectcategory=" OR TgtProcCmdLine containsCIS "-subnets -f" OR TgtProcCmdLine containsCIS "name=\"Domain Admins\"" OR TgtProcCmdLine containsCIS "-sc u:" OR TgtProcCmdLine containsCIS "domainncs" OR TgtProcCmdLine containsCIS "dompol" OR TgtProcCmdLine containsCIS " oudmp " OR TgtProcCmdLine containsCIS "subnetdmp" OR TgtProcCmdLine containsCIS "gpodmp" OR TgtProcCmdLine containsCIS "fspdmp" OR TgtProcCmdLine containsCIS "users_noexpire" OR TgtProcCmdLine containsCIS "computers_active" OR TgtProcCmdLine containsCIS "computers_pwdnotreqd"))

```