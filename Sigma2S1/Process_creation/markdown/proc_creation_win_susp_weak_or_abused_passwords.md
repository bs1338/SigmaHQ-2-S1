# proc_creation_win_susp_weak_or_abused_passwords

## Title
Weak or Abused Passwords In CLI

## ID
91edcfb1-2529-4ac2-9ecc-7617f895c7e4

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-14

## Tags
attack.defense-evasion, attack.execution

## Description
Detects weak passwords or often abused passwords (seen used by threat actors) via the CLI.
An example would be a threat actor creating a new user via the net command and providing the password inline


## References
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/espionage-asia-governments
https://thedfirreport.com/2022/09/26/bumblebee-round-two/
https://www.microsoft.com/en-us/security/blog/2022/10/25/dev-0832-vice-society-opportunistic-ransomware-campaigns-impacting-us-education-sector/
https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## False Positives
Legitimate usage of the passwords by users via commandline (should be discouraged)
Other currently unknown false positives

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "123456789" OR TgtProcCmdLine containsCIS "123123qwE" OR TgtProcCmdLine containsCIS "Asd123.aaaa" OR TgtProcCmdLine containsCIS "Decryptme" OR TgtProcCmdLine containsCIS "P@ssw0rd!" OR TgtProcCmdLine containsCIS "Pass8080" OR TgtProcCmdLine containsCIS "password123" OR TgtProcCmdLine containsCIS "test@202"))

```