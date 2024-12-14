# proc_creation_win_susp_double_extension

## Title
Suspicious Double Extension File Execution

## ID
1cdd9a09-06c9-4769-99ff-626e2b3991b8

## Author
Florian Roth (Nextron Systems), @blu3_team (idea), Nasreddine Bencherchali (Nextron Systems)

## Date
2019-06-26

## Tags
attack.initial-access, attack.t1566.001

## Description
Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns

## References
https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html
https://twitter.com/blackorbird/status/1140519090961825792

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".doc.exe" OR TgtProcCmdLine containsCIS ".docx.exe" OR TgtProcCmdLine containsCIS ".xls.exe" OR TgtProcCmdLine containsCIS ".xlsx.exe" OR TgtProcCmdLine containsCIS ".ppt.exe" OR TgtProcCmdLine containsCIS ".pptx.exe" OR TgtProcCmdLine containsCIS ".rtf.exe" OR TgtProcCmdLine containsCIS ".pdf.exe" OR TgtProcCmdLine containsCIS ".txt.exe" OR TgtProcCmdLine containsCIS "      .exe" OR TgtProcCmdLine containsCIS "______.exe" OR TgtProcCmdLine containsCIS ".doc.js" OR TgtProcCmdLine containsCIS ".docx.js" OR TgtProcCmdLine containsCIS ".xls.js" OR TgtProcCmdLine containsCIS ".xlsx.js" OR TgtProcCmdLine containsCIS ".ppt.js" OR TgtProcCmdLine containsCIS ".pptx.js" OR TgtProcCmdLine containsCIS ".rtf.js" OR TgtProcCmdLine containsCIS ".pdf.js" OR TgtProcCmdLine containsCIS ".txt.js") AND (TgtProcImagePath endswithCIS ".doc.exe" OR TgtProcImagePath endswithCIS ".docx.exe" OR TgtProcImagePath endswithCIS ".xls.exe" OR TgtProcImagePath endswithCIS ".xlsx.exe" OR TgtProcImagePath endswithCIS ".ppt.exe" OR TgtProcImagePath endswithCIS ".pptx.exe" OR TgtProcImagePath endswithCIS ".rtf.exe" OR TgtProcImagePath endswithCIS ".pdf.exe" OR TgtProcImagePath endswithCIS ".txt.exe" OR TgtProcImagePath endswithCIS "      .exe" OR TgtProcImagePath endswithCIS "______.exe" OR TgtProcImagePath endswithCIS ".doc.js" OR TgtProcImagePath endswithCIS ".docx.js" OR TgtProcImagePath endswithCIS ".xls.js" OR TgtProcImagePath endswithCIS ".xlsx.js" OR TgtProcImagePath endswithCIS ".ppt.js" OR TgtProcImagePath endswithCIS ".pptx.js" OR TgtProcImagePath endswithCIS ".rtf.js" OR TgtProcImagePath endswithCIS ".pdf.js" OR TgtProcImagePath endswithCIS ".txt.js")))

```