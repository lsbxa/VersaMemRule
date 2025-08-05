# VersaMemRule
A YARA rule to detect *VersaMem* malware samples

*VersaMem* is a malware used by the Chinese APT group Volt Typhoon, deployed after exploiting a zero-day vulnerability (CVE-2024-39717).

The malware injects code into the Tomcat process, silently deploying a webshell and a keylogger.

During the static analysis, we identified several indicators related to this malware, such as suspicious strings, class names and unusual file paths.

These signatures were used as the basis for creating this YARA rule.

```powershell
yara.exe VersaMemRule.yar VersaMem.jar
```

![VersaMemAct](https://github.com/user-attachments/assets/235cc2af-d75d-4a51-832b-ef3a987e6e8d)

## References:
https://bazaar.abuse.ch/sample/4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37/#yara
https://www.cybersecuritydive.com/news/volt-typhoon-zero-day-isps-msps/725492/
https://nvd.nist.gov/vuln/detail/cve-2024-39717
