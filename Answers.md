# Answers to Part 3

Add your answers to the questions in Part 3, Step 2 below. 

## Vulernability Remediation:

### Vulnerability 1: CVE-2019-20477

**CVE Details:**
CVE-2019-20477 is a deserialization vulnerability in PyYAML versions 5.1 through 5.1.2. The vulnerability involves insufficient restrictions on the `load` and `load_all` functions due to a class deserialization issue. Attackers can exploit this by deserializing untrusted data, potentially instantiating dangerous classes like `Popen` from the subprocess module, leading to arbitrary code execution.

**CVSS Score:** 9.3 (CRITICAL)  
**Affected Package:** pkg:pypi/pyyaml@5.1  
**Affected Range:** >=5.1,<5.2

**Recommended Remediation:**
Upgrade PyYAML from version 5.1 to version **5.2** or later. This fix addresses the incomplete patch from CVE-2017-18342 and properly restricts class deserialization in the load functions.

---

### Vulnerability 2: CVE-2020-14343

**CVE Details:**
CVE-2020-14343 is an arbitrary code execution vulnerability in PyYAML versions before 5.4. The library is susceptible to code execution when processing untrusted YAML files through the `full_load` method or with the `FullLoader` loader due to improper input validation. Attackers can abuse the `python/object/new` constructor to execute arbitrary code on the system. This is an incomplete fix for CVE-2020-1747.

**CVSS Score:** 9.3 (CRITICAL)  
**Affected Package:** pkg:pypi/pyyaml@5.1  
**Affected Range:** <5.4

**Recommended Remediation:**
Upgrade PyYAML from version 5.1 to version **5.4** or later. This version properly addresses the arbitrary code execution vulnerability by fixing the improper input validation in the FullLoader.

---

## Summary

Both critical vulnerabilities affect the same PyYAML 5.1 package currently in use. The most comprehensive remediation is to **upgrade PyYAML to version 5.4 or later**, which addresses both CVE-2019-20477 and CVE-2020-14343, as well as CVE-2020-1747 (also listed as CRITICAL in the report).
