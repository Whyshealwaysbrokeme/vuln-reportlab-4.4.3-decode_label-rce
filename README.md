# TensorFlow <= 2.20.0 - Remote Code Execution (SavedModel Deserialization)

This repository contains a security advisory for the `tensorflow` package (PyPI, TensorFlow project).  
The issue allows **Remote Code Execution (RCE)** due to unsafe deserialization in `tf.saved_model.load`, which restores arbitrary Python functions (e.g. `tf.py_function`) embedded in a malicious SavedModel.

## Details
- **Affected Product:** TensorFlow (`tensorflow`)
- **Affected Version:** <= 2.20.0 (latest tested)
- **Vulnerability Type:** Insecure Deserialization / Remote Code Execution
- **Severity:** Critical
- **CVSS Score:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Related CWE:** CWE-502 (Deserialization of Untrusted Data)

## Impact
Successful exploitation allows attackers to craft a malicious SavedModel that,
when loaded via `tf.saved_model.load`, executes arbitrary Python code on the victim machine.
This can lead to:
- Remote Code Execution (arbitrary system commands)
- Full compromise of the affected host
- Data theft, modification, or deletion
- Escalation of privileges or persistence in ML pipelines

## Files
- [`report/report.md`](./report/report.md) – Full vulnerability report  
- [`report/poc.py`](./report/poc.py) – Proof of Concept script  
- [`report/poc.png`](./report/poc.png) – Screenshot of PoC script  
- [`report/output.png`](./report/output.png) – Execution result screenshot  

## Mitigation
- Do not load untrusted SavedModel files without strict validation  
- TensorFlow should restrict or block the use of `tf.py_function` and similar Python execution primitives during model deserialization  
- Introduce a "safe mode" for `tf.saved_model.load` to only restore computation graphs  
- Users should sandbox model loading and verify sources of pretrained models  

## Disclosure
- **Status:** Under responsible disclosure  
- **Disclosure Date:** 24 August 2025  
- **Reporter:** Manopakorn Kooharueangrong (Whyshealwaysbrokeme)
