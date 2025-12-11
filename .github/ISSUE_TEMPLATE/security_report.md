---
name: Security vulnerability report
about: Report a security vulnerability (use private reporting when possible)
title: '[SECURITY] '
labels: 'security'
assignees: ''

---

**⚠️ IMPORTANT: For serious security vulnerabilities, please use GitHub's private vulnerability reporting feature or email security@yourproject.com instead of creating a public issue.**

**Vulnerability Type**
- [ ] Input validation issue
- [ ] Authentication/authorization bypass
- [ ] Information disclosure
- [ ] Code injection
- [ ] Denial of service
- [ ] Cryptographic issue
- [ ] Other: [specify]

**Severity Assessment**
- [ ] Critical (remote code execution, authentication bypass)
- [ ] High (privilege escalation, significant data exposure)
- [ ] Medium (limited information disclosure, DoS)
- [ ] Low (minor information leakage, configuration issues)

**Affected Components**
- [ ] ExploitEngine
- [ ] PayloadGenerator
- [ ] OOBListener
- [ ] ConfigurationManager
- [ ] SessionManager
- [ ] ErrorHandler
- [ ] PayloadEvasion
- [ ] Main module (react2shell_rce.rb)
- [ ] Other: [specify]

**Vulnerability Description**
A clear and concise description of the security vulnerability.

**Attack Scenario**
Describe how an attacker could exploit this vulnerability:
1. Step 1
2. Step 2
3. Step 3

**Impact**
Describe the potential impact of this vulnerability:
- What could an attacker achieve?
- What data or systems could be compromised?
- What is the scope of the impact?

**Proof of Concept**
```ruby
# Provide a minimal proof of concept (remove any sensitive details)
```

**Affected Versions**
- Version range: [e.g. 1.0.0 - 1.2.0]
- Specific commit: [if known]

**Environment Details**
- OS: [e.g. Ubuntu 20.04]
- Ruby version: [e.g. 3.0.0]
- Metasploit version: [e.g. 6.3.4]

**Suggested Fix**
If you have suggestions for fixing this vulnerability:
```ruby
# Suggested code changes or approach
```

**References**
- Related CVEs: [if any]
- Security advisories: [if any]
- Documentation: [relevant security documentation]

**Disclosure Timeline**
- Discovery date: [when you discovered this]
- Vendor notification: [when you plan to/did notify]
- Public disclosure: [planned disclosure date]

**Reporter Information**
- Name: [your name or handle]
- Affiliation: [organization, if applicable]
- Contact: [preferred contact method]
- PGP Key: [if you use PGP]

**Responsible Disclosure**
- [ ] I agree to follow responsible disclosure practices
- [ ] I will not publicly disclose details until a fix is available
- [ ] I will coordinate with the project maintainers on disclosure timing
- [ ] I understand this may be a duplicate of a previously reported issue

**Legal and Ethical Compliance**
- [ ] I discovered this vulnerability through authorized testing only
- [ ] I have not accessed any systems without permission
- [ ] I have not disclosed this vulnerability to others
- [ ] I understand the legal implications of security research in my jurisdiction

---

**For Maintainers:**
- [ ] Vulnerability confirmed
- [ ] Severity assessed
- [ ] Fix developed
- [ ] Fix tested
- [ ] Security advisory prepared
- [ ] Coordinated disclosure planned