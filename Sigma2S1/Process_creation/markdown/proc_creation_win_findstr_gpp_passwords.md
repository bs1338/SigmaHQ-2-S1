# proc_creation_win_findstr_gpp_passwords

## Title
Findstr GPP Passwords

## ID
91a2c315-9ee6-4052-a853-6f6a8238f90d

## Author
frack113

## Date
2021-12-27

## Tags
attack.credential-access, attack.t1552.006

## Description
Look for the encrypted cpassword value within Group Policy Preference files on the Domain Controller. This value can be decrypted with gpp-decrypt.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.006/T1552.006.md#atomic-test-1---gpp-passwords-findstr

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "cpassword" AND TgtProcCmdLine containsCIS "\sysvol\" AND TgtProcCmdLine containsCIS ".xml") AND (TgtProcImagePath endswithCIS "\find.exe" OR TgtProcImagePath endswithCIS "\findstr.exe")))

```