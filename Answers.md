# Answers to Part 3

Add your answers to the questions in Part 3, Step 2 below. 

## Vulernability Remediation (Scout):

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

### Summary

Both critical vulnerabilities affect the same PyYAML 5.1 package currently in use. The most comprehensive remediation is to **upgrade PyYAML to version 5.4 or later**, which addresses both CVE-2019-20477 and CVE-2020-14343, as well as CVE-2020-1747 (also listed as CRITICAL in the report).

---

## Vulernability Remediation (Trivy):

### Vulnerability 1: CVE-2023-50447

**CVE Details:**
CVE-2023-50447 affects Pillow versions through 10.1.0 and allows arbitrary code execution via the environment parameter in `PIL.ImageMath.eval`. This is a distinct vulnerability from CVE-2022-22817 (which involved the expression parameter). Attackers can exploit this to execute arbitrary code on the system by manipulating the environment parameter when the ImageMath.eval function is called.

**CVSS Score:** 9.3 (CRITICAL) - Security Severity: 8.1  
**Affected Package:** Pillow@9.4.0  
**Affected Range:** <10.2.0

**Recommended Remediation:**
Upgrade Pillow from version 9.4.0 to version **10.2.0** or later. This version properly addresses the arbitrary code execution vulnerability by fixing the handling of the environment parameter in PIL.ImageMath.eval.

---

### Vulnerability 2: CVE-2019-20477

**CVE Details:**
CVE-2019-20477 is a deserialization vulnerability in PyYAML versions 5.1 through 5.1.2. The vulnerability stems from insufficient restrictions on the `load` and `load_all` functions, allowing class deserialization issues. Attackers can exploit this by deserializing untrusted YAML data, potentially instantiating dangerous classes like `Popen` from the subprocess module, leading to arbitrary command execution. This vulnerability exists because of an incomplete fix for CVE-2017-18342.

**CVSS Score:** 9.8 (CRITICAL)  
**Affected Package:** PyYAML@5.1  
**Affected Range:** >=5.1,<5.2

**Recommended Remediation:**
Upgrade PyYAML from version 5.1 to version **5.2** or later. However, note that PyYAML 5.1 is also affected by CVE-2020-14343 and CVE-2020-1747, so upgrading to version **5.4** or later is the most comprehensive remediation to address all three critical vulnerabilities simultaneously.

---

### Vulnerability 3: CVE-2020-14343

**CVE Details:**
CVE-2020-14343 affects PyYAML versions before 5.4 and enables arbitrary code execution when processing untrusted YAML files through the `full_load` method or with the `FullLoader` loader. The vulnerability allows attackers to abuse the `python/object/new` constructor to execute arbitrary code on the system. This is an incomplete fix for CVE-2020-1747.

**CVSS Score:** 9.8 (CRITICAL)  
**Affected Package:** PyYAML@5.1  
**Affected Range:** <5.4

**Recommended Remediation:**
Upgrade PyYAML from version 5.1 to version **5.4** or later to comprehensively address this vulnerability along with related CVEs.

---

### Vulnerability 4: CVE-2020-1747

**CVE Details:**
CVE-2020-1747 is an arbitrary code execution vulnerability in PyYAML versions before 5.3.1. When applications process untrusted YAML files using the `full_load` method or `FullLoader` loader, attackers can exploit the `python/object/new` constructor to execute arbitrary code on the system.

**CVSS Score:** 9.8 (CRITICAL)  
**Affected Package:** PyYAML@5.1  
**Affected Range:** >=5.1b7,<5.3.1

**Recommended Remediation:**
Upgrade PyYAML to version **5.3.1** or later, though version **5.4** or later is recommended to address all related vulnerabilities.

---

### Summary and Consolidated Recommendation

The PyGoat application has **four CRITICAL severity vulnerabilities**:
- **Pillow 9.4.0**: Upgrade to **10.2.0** or later
- **PyYAML 5.1**: Upgrade to **5.4** or later (addresses CVE-2019-20477, CVE-2020-14343, and CVE-2020-1747)

These upgrades should be prioritized immediately as all four vulnerabilities allow for arbitrary code execution, representing severe security risks to the application.