# ReportLab <= 4.4.3 - Remote Code Execution (decode_label Deserialization)

This repository contains a security advisory for the `reportlab` package (PyPI, ReportLab project).  
The issue allows **Remote Code Execution (RCE)** due to unsafe deserialization in `reportlab.lib.utils.decode_label`, which directly calls `pickle.loads()` on base64-decoded user input.

## Details
- **Affected Product:** ReportLab (`reportlab`)
- **Affected Version:** <= 4.4.3 (latest tested)
- **Vulnerability Type:** Insecure Deserialization / Remote Code Execution
- **Severity:** Critical
- **CVSS Score:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Related CWE:** CWE-502 (Deserialization of Untrusted Data)

## Impact
Successful exploitation allows attackers to craft a malicious base64-encoded pickle payload that,
when passed to `utils.decode_label`, executes arbitrary Python code on the victim machine.
This can lead to:
- Remote Code Execution (arbitrary system commands)
- Full compromise of the affected host
- Data theft, modification, or deletion
- Escalation of privileges or persistence in applications using ReportLab

## Files
- [`report/report.md`](./report/report.md) – Full vulnerability report  
- [`report/poc.py`](./report/poc.py) – Proof of Concept script  
- [`report/poc.png`](./report/poc.png) – Screenshot of PoC script  
- [`report/output.png`](./report/output.png) – Execution result screenshot  

## Mitigation
- Do not use `pickle.loads()` on untrusted input  
- Replace pickle with a safe serialization format such as JSON  
- Add explicit warnings in documentation about unsafe functions  
- Consider removing or deprecating `decode_label()` to avoid misuse  

## Disclosure
- **Status:** Under responsible disclosure  
- **Disclosure Date:** 25 August 2025  
- **Reporter:** Manopakorn Kooharueangrong (Whyshealwaysbrokeme)
