# Terraform Secure Code Generation Rules

## Foundational Instructions for the LLM
- As a security-aware developer, generate secure Terraform code using any that inherently prevents top security weaknesses.
- Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
- Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
- Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
- **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

## Common Weakness Enumerations (CWEs) for Terraform + any

### CWE-798: Use of Hard-coded Credentials
**Summary:** The use of hard-coded credentials significantly increases the risk of unauthorized access.
**Mitigation Rule:** Never include credentials directly in Terraform files. Use environment variables or secret management tools like AWS Secrets Manager or HashiCorp Vault to manage sensitive data securely.

### CWE-89: SQL Injection
**Summary:** SQL injection occurs when user input is improperly sanitized, allowing execution of arbitrary SQL code.
**Mitigation Rule:** Always validate and sanitize user inputs. Use parameterized queries or ORM libraries that are secure by default to prevent SQL injection.

### CWE-79: Cross-site Scripting (XSS)
**Summary:** XSS vulnerabilities occur when an application includes untrusted data in a web page without proper validation or escaping.
**Mitigation Rule:** Ensure all user input is properly escaped when included in web pages. Use libraries or frameworks that automatically handle output encoding to prevent XSS.

### CWE-22: Path Traversal
**Summary:** Path traversal vulnerabilities allow attackers to access files outside of the intended directory.
**Mitigation Rule:** Sanitize and validate all user inputs used in file paths. Use APIs that abstract file path creation to prevent directory traversal.

### CWE-200: Exposure of Sensitive Information
**Summary:** Sensitive information exposure occurs when an application unintentionally reveals confidential data.
**Mitigation Rule:** Avoid logging sensitive data. Use secure protocols and encrypt sensitive information both at rest and in transit.

### CWE-20: Improper Input Validation
**Summary:** Improper input validation occurs when an application fails to properly check the validity of input data.
**Mitigation Rule:** Implement strict input validation on all user inputs. Use whitelisting to allow only known safe values.

### CWE-120: Buffer Overflow
**Summary:** Buffer overflow occurs when data exceeds the storage capacity of a buffer, leading to adjacent memory corruption.
**Mitigation Rule:** Always check buffer sizes and use memory-safe libraries or languages whenever possible to prevent buffer overflow vulnerabilities.
```
