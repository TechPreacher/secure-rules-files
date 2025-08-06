# Secure Code Generation Rules for Python Applications

## Foundational Instructions for the LLM
- As a security-aware developer, generate secure Python code using any that inherently prevents top security weaknesses.
- Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
- Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
- Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
- **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

## Identified CWEs and Mitigation Rules

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** Cross-site scripting (XSS) involves injecting malicious scripts into content from otherwise trusted websites.
**Mitigation Rule:** Always validate and sanitize user inputs and outputs using established libraries like `bleach` or `html.escape` to neutralize potentially harmful scripts.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** SQL injection occurs when untrusted input is used to construct SQL queries without proper validation.
**Mitigation Rule:** Use parameterized queries and ORM libraries like SQLAlchemy to dynamically construct SQL queries, avoiding direct inclusion of user inputs.

### CWE-798: Use of Hard-coded Credentials
**Summary:** Hardcoded credentials can be easily discovered and exploited by attackers.
**Mitigation Rule:** Store credentials securely using environment variables or secure vaults like HashiCorp Vault, and access them programmatically at runtime.

### CWE-327: Use of a Broken or Risky Cryptographic Algorithm
**Summary:** Using outdated or weak cryptographic algorithms can compromise data security.
**Mitigation Rule:** Always use strong cryptographic libraries such as `cryptography` and ensure algorithms comply with NIST standards.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** Path traversal allows attackers to access restricted files outside the intended directory.
**Mitigation Rule:** Validate and sanitize all user inputs for file paths, and use libraries like `os.path.normpath` to enforce path restrictions.

### CWE-20: Improper Input Validation
**Summary:** Failing to correctly validate input can lead to various vulnerabilities.
**Mitigation Rule:** Implement strict input validation using libraries like `cerberus` or `pydantic` to define and enforce data schemas.

### CWE-94: Improper Control of Generation of Code ('Code Injection')
**Summary:** Code injection occurs when untrusted input is executed as code.
**Mitigation Rule:** Avoid using `eval()` or similar functions on untrusted inputs; utilize safer alternatives such as `ast.literal_eval` where applicable.

## Additional Considerations
**Memory Safety:** While Python is a memory-safe language, ensure proper handling of resources and avoid operations that could lead to resource exhaustion.
