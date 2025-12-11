# Contributing to React2Shell Metasploit Module

Thank you for your interest in contributing to the React2Shell Metasploit Module! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Security Considerations](#security-considerations)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project adheres to a code of conduct that promotes a welcoming and inclusive environment:

### Our Standards

- **Be respectful**: Treat all contributors with respect and professionalism
- **Be inclusive**: Welcome contributors from all backgrounds and experience levels
- **Be collaborative**: Work together constructively and share knowledge
- **Be responsible**: Use this tool ethically and legally
- **Be constructive**: Provide helpful feedback and suggestions

### Unacceptable Behavior

- Harassment, discrimination, or offensive language
- Sharing malicious code or exploits
- Discussing illegal activities or unauthorized testing
- Personal attacks or trolling
- Spam or off-topic discussions

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Ruby 2.7+** installed
- **Metasploit Framework** (for testing integration)
- **Git** for version control
- **Basic understanding** of Ruby and security concepts

### First Contribution

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Set up the development environment**
4. **Find an issue** to work on or propose a new feature
5. **Make your changes** following our guidelines
6. **Submit a pull request**

## Development Setup

### 1. Clone and Setup

```bash
# Clone your fork
git clone https://github.com/your-username/react2shell-metasploit-oob.git
cd react2shell-metasploit-oob

# Add upstream remote
git remote add upstream https://github.com/original-repo/react2shell-metasploit-oob.git

# Install dependencies
bundle install
```

### 2. Verify Installation

```bash
# Run verification script
ruby verify_setup.rb

# Run test suite
bundle exec rspec

# Check code style
bundle exec rubocop
```

### 3. Development Workflow

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and test
# ... your development work ...

# Run tests
bundle exec rspec

# Check code style
bundle exec rubocop

# Commit changes
git add .
git commit -m "Add: descriptive commit message"

# Push to your fork
git push origin feature/your-feature-name
```

## Contributing Guidelines

### Types of Contributions

We welcome various types of contributions:

#### 🐛 Bug Reports
- Use the issue template
- Include steps to reproduce
- Provide system information
- Include relevant logs or error messages

#### ✨ Feature Requests
- Describe the use case
- Explain the expected behavior
- Consider security implications
- Discuss implementation approach

#### 🔧 Code Contributions
- Bug fixes
- New payload methods
- Evasion techniques
- Performance improvements
- Documentation updates

#### 📚 Documentation
- README improvements
- Code comments
- Usage examples
- Security guidelines

### Contribution Areas

#### High Priority
- **Security improvements**: Input validation, error handling
- **Payload methods**: New exfiltration techniques
- **Evasion techniques**: WAF bypass methods
- **Error handling**: Better error messages and recovery
- **Testing**: Property-based tests and edge cases

#### Medium Priority
- **Performance**: Optimization of data transfers
- **Usability**: Better configuration options
- **Compatibility**: Support for different environments
- **Documentation**: Usage examples and guides

#### Low Priority
- **Refactoring**: Code organization improvements
- **Logging**: Enhanced debugging capabilities
- **Utilities**: Helper scripts and tools

## Pull Request Process

### Before Submitting

1. **Update your branch** with latest upstream changes
2. **Run the full test suite** and ensure all tests pass
3. **Check code style** with RuboCop
4. **Update documentation** if needed
5. **Test manually** with different configurations

### PR Requirements

- **Clear title** describing the change
- **Detailed description** of what was changed and why
- **Reference related issues** using `#issue-number`
- **Include test cases** for new functionality
- **Update documentation** as needed
- **Follow coding standards**

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Security Review
- [ ] No sensitive information exposed
- [ ] Input validation implemented
- [ ] Error handling secure

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

### Review Process

1. **Automated checks** must pass (CI/CD)
2. **Code review** by maintainers
3. **Security review** for security-related changes
4. **Testing** in different environments
5. **Approval** and merge

## Coding Standards

### Ruby Style Guide

We follow the [Ruby Style Guide](https://rubystyle.guide/) with some modifications:

#### General Principles
- **Clarity over cleverness**: Write clear, readable code
- **Consistency**: Follow existing patterns in the codebase
- **Security first**: Always consider security implications
- **Documentation**: Comment complex logic and security considerations

#### Specific Guidelines

```ruby
# Good: Clear method names and documentation
def create_file_exfiltration_payload(filepath, oob_url, options = {})
  # Validate input parameters for security
  raise ArgumentError, "Filepath cannot be nil" if filepath.nil?
  
  # Implementation...
end

# Good: Proper error handling
begin
  result = risky_operation
rescue SpecificError => e
  handle_error(e, context: 'operation_name')
  raise e
end

# Good: Security-conscious input validation
def validate_filepath(filepath)
  return false if filepath.nil? || filepath.empty?
  return false unless filepath.start_with?('/')
  return false if filepath.include?('..')
  true
end
```

#### Code Organization

```ruby
# File structure
class ComponentName
  # Constants first
  DEFAULT_TIMEOUT = 30
  
  # Attributes
  attr_reader :config, :logger
  
  # Initialize
  def initialize(options = {})
    # Implementation
  end
  
  # Public methods
  def public_method
    # Implementation
  end
  
  private
  
  # Private methods
  def private_method
    # Implementation
  end
end
```

### Security Coding Standards

#### Input Validation
```ruby
# Always validate and sanitize inputs
def process_command(command)
  raise ArgumentError, "Command cannot be nil" if command.nil?
  raise ArgumentError, "Command cannot be empty" if command.empty?
  
  # Validate against dangerous patterns
  dangerous_patterns = [/rm\s+-rf\s+\//, /:\(\)\{.*\}/]
  if dangerous_patterns.any? { |pattern| command =~ pattern }
    logger.warn("Potentially dangerous command detected")
  end
  
  # Escape for shell execution
  escaped_command = escape_shell_parameter(command)
  # Process...
end
```

#### Error Handling
```ruby
# Secure error messages (don't leak sensitive info)
def handle_network_error(error, context)
  # Log detailed error internally
  logger.error("Network error in #{context}: #{error.class}: #{error.message}")
  
  # Return generic error to user
  "Network connection failed. Check connectivity and try again."
end
```

## Testing Requirements

### Test Categories

#### Unit Tests
- Test individual methods and classes
- Mock external dependencies
- Cover edge cases and error conditions
- Aim for >90% code coverage

```ruby
RSpec.describe PayloadGenerator do
  describe '#create_file_exfiltration_payload' do
    it 'generates valid wget payload' do
      payload = subject.create_file_exfiltration_payload('/etc/passwd', 'http://example.com')
      expect(payload).to include('wget')
      expect(payload).to include('/etc/passwd')
    end
    
    it 'raises error for invalid filepath' do
      expect {
        subject.create_file_exfiltration_payload(nil, 'http://example.com')
      }.to raise_error(ArgumentError)
    end
  end
end
```

#### Property-Based Tests
- Test universal properties across many inputs
- Use rspec-quickcheck for random input generation
- Minimum 100 iterations per property

```ruby
RSpec.describe PayloadGenerator do
  include RSpec::QuickCheck
  
  property 'payload escaping is reversible' do
    forall(string) do |input|
      escaped = subject.escape_javascript(input)
      # Property: escaping should not break valid JavaScript
      expect(escaped).not_to include("'")
      expect(escaped).not_to include('"')
    end
  end
end
```

#### Integration Tests
- Test component interactions
- Test with real network conditions (when safe)
- Test error recovery scenarios

### Running Tests

```bash
# Run all tests
bundle exec rspec

# Run specific test file
bundle exec rspec spec/lib/react2shell/payload_generator_spec.rb

# Run with coverage
bundle exec rspec --format documentation

# Run property-based tests only
bundle exec rspec --tag property

# Run integration tests
bundle exec rspec --tag integration
```

## Security Considerations

### Security Review Process

All contributions undergo security review:

1. **Automated security scanning** (if available)
2. **Manual code review** focusing on:
   - Input validation
   - Output encoding
   - Error handling
   - Authentication/authorization
   - Cryptographic usage

### Security Guidelines for Contributors

#### Input Validation
- **Validate all inputs** at entry points
- **Use allowlists** instead of blocklists when possible
- **Sanitize data** before processing
- **Check for injection attacks** (command injection, path traversal)

#### Error Handling
- **Don't leak sensitive information** in error messages
- **Log security events** appropriately
- **Fail securely** (deny by default)
- **Handle edge cases** gracefully

#### Network Security
- **Validate SSL/TLS certificates** when required
- **Use secure protocols** (HTTPS over HTTP)
- **Implement timeouts** to prevent hanging
- **Handle network errors** gracefully

### Prohibited Contributions

- **Malicious code** or backdoors
- **Hardcoded credentials** or secrets
- **Unnecessary privileges** or permissions
- **Insecure cryptographic practices**
- **Code that facilitates illegal activities**

## Documentation

### Documentation Standards

#### Code Documentation
```ruby
##
# Creates a payload for file exfiltration via wget
# @param filepath [String] Absolute path to file to exfiltrate
# @param oob_url [String] URL for OOB callback
# @param options [Hash] Additional options
# @option options [Integer] :chunk_size Size for chunked transfers
# @return [String] Shell command for file exfiltration
# @raise [ArgumentError] If filepath is invalid
def create_file_exfiltration_payload(filepath, oob_url, options = {})
  # Implementation...
end
```

#### README Updates
- Update usage examples for new features
- Document new configuration options
- Add troubleshooting information
- Update compatibility information

#### Security Documentation
- Document security implications of changes
- Update threat model if needed
- Add security configuration examples
- Document new attack vectors or mitigations

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Security Issues**: Use private security reporting

### Getting Help

- **Documentation**: Check README.md and code comments
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Ask questions in GitHub Discussions
- **Code Review**: Request review from maintainers

### Recognition

Contributors are recognized through:

- **GitHub contributors list**
- **Release notes** mentioning significant contributions
- **Security acknowledgments** for security improvements
- **Documentation credits** for major documentation work

## Release Process

### Version Numbering

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] Security review completed
- [ ] Version number updated
- [ ] Release notes prepared
- [ ] Compatibility tested

---

Thank you for contributing to the React2Shell Metasploit Module! Your contributions help make security research more effective and accessible.

**Questions?** Feel free to open an issue or start a discussion.

**Security Concerns?** Please follow our [Security Policy](SECURITY.md) for responsible disclosure.