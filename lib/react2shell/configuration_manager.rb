# frozen_string_literal: true

require 'uri'
require 'socket'
require 'timeout'
require 'ipaddr'
require 'openssl'
require_relative 'error_handler'

module React2Shell
  ##
  # ConfigurationManager - Handles parameter validation and configuration
  # Validates network settings and provides configuration access
  class ConfigurationManager
    attr_reader :msf_module, :error_handler

    def initialize(msf_module)
      @msf_module = msf_module
      @error_handler = ErrorHandler.new(msf_module)
    end

    ##
    # Validates all module options and connectivity
    # @return [Array<String>] Array of validation errors (empty if valid)
    def validate_options
      errors = []
      
      # Validate required options
      errors << "RHOSTS not set" if @msf_module.datastore['RHOSTS'].to_s.empty?
      errors << "LHOST not set" if @msf_module.datastore['LHOST'].to_s.empty?
      
      # Validate RHOSTS format
      rhosts = @msf_module.datastore['RHOSTS'].to_s.strip
      unless valid_host_format?(rhosts)
        errors << "RHOSTS contains invalid host format"
      end
      
      # Validate LHOST format
      lhost = @msf_module.datastore['LHOST'].to_s.strip
      unless valid_host_format?(lhost)
        errors << "LHOST contains invalid host format"
      end
      
      # Validate port ranges
      rport = @msf_module.datastore['RPORT']
      if rport && (rport < 1 || rport > 65535)
        errors << "RPORT must be between 1 and 65535"
      end
      
      srvport = @msf_module.datastore['SRVPORT']
      if srvport && (srvport < 1 || srvport > 65535)
        errors << "SRVPORT must be between 1 and 65535"
      end
      
      # Validate exploit mode parameters
      filepath = @msf_module.datastore['FILEPATH'].to_s.strip
      command = @msf_module.datastore['CMD'].to_s.strip
      
      if filepath.empty? && command.empty?
        errors << "Either FILEPATH or CMD must be specified"
      end
      
      if !filepath.empty? && !command.empty?
        errors << "Cannot specify both FILEPATH and CMD - choose one"
      end
      
      # Validate file path format
      if !filepath.empty? && !filepath.start_with?('/')
        errors << "FILEPATH must be an absolute path starting with /"
      end
      
      # Validate network configuration
      network_errors = validate_network_configuration
      errors.concat(network_errors)
      
      errors
    end

    ##
    # Checks basic connectivity to target with comprehensive validation
    # Implements requirement 1.2: validate connectivity before sending exploit
    # @return [Boolean] True if target is reachable
    def check_connectivity
      @msf_module.print_status("Checking connectivity to target...")
      retry_count = 0
      max_retries = 3
      
      begin
        # Detect and configure SSL/TLS automatically (requirement 1.5)
        ssl_detected = detect_ssl_requirement
        if ssl_detected != @msf_module.datastore['SSL']
          @msf_module.print_status("Auto-detected SSL requirement: #{ssl_detected}")
          @msf_module.datastore['SSL'] = ssl_detected
        end
        
        # Perform connectivity check with proper SSL handling
        response = @msf_module.send_request_cgi({
          'method' => 'GET',
          'uri' => @msf_module.normalize_uri(@msf_module.target_uri.path),
          'ssl' => use_ssl?
        })
        
        if response.nil?
          error_info = @error_handler.handle_network_error(
            StandardError.new("No response received from target"),
            "connectivity check",
            retry_count
          )
          return false
        end
        
        # Validate response indicates a web server (requirement 1.4)
        if validate_http_response(response)
          @msf_module.vprint_good("Target is reachable and responding")
          return true
        else
          @msf_module.vprint_error("Target responded but may not be a valid web server")
          return false
        end
        
      rescue => e
        # Use centralized error handling with retry logic
        error_info = @error_handler.handle_network_error(e, "connectivity check", retry_count)
        
        # Implement automatic retry for network errors (requirement 4.3)
        if error_info[:should_retry] && retry_count < max_retries
          retry_count += 1
          sleep(@error_handler.send(:calculate_retry_delay, retry_count - 1))
          retry
        end
        
        # Special handling for SSL errors with automatic fallback
        if e.class.name =~ /SSL/ && use_ssl?
          @msf_module.print_status("SSL failed, attempting HTTP fallback...")
          @msf_module.datastore['SSL'] = false
          return check_connectivity_fallback
        end
        
        false
      end
    end

    ##
    # Gets the OOB callback URL
    # @return [String] Complete OOB URL for callbacks
    def get_oob_url
      host = get_listener_host
      port = get_listener_port
      protocol = determine_protocol
      
      "#{protocol}://#{host}:#{port}/"
    end

    ##
    # Gets the listener address string for display
    # @return [String] Listener address in host:port format
    def get_listener_address
      "#{get_listener_host}:#{get_listener_port}"
    end

    ##
    # Determines the exploit mode based on parameters
    # @return [Symbol] :file_exfiltration or :command_execution
    def determine_exploit_mode
      filepath = @msf_module.datastore['FILEPATH'].to_s.strip
      command = @msf_module.datastore['CMD'].to_s.strip
      
      if !command.empty?
        :command_execution
      elsif !filepath.empty?
        :file_exfiltration
      else
        raise ArgumentError, "No valid exploit mode could be determined"
      end
    end

    ##
    # Gets the file path for exfiltration
    # @return [String] File path to exfiltrate
    def get_filepath
      @msf_module.datastore['FILEPATH'].to_s.strip
    end

    ##
    # Gets the command for execution
    # @return [String] Command to execute
    def get_command
      @msf_module.datastore['CMD'].to_s.strip
    end

    ##
    # Gets the HTTP delay timeout
    # @return [Integer] Timeout in seconds
    def get_http_delay
      @msf_module.datastore['HTTP_DELAY'] || 10
    end

    ##
    # Gets the listener host
    # @return [String] Host for OOB listener
    def get_listener_host
      @msf_module.datastore['SRVHOST'] || @msf_module.datastore['LHOST'] || '0.0.0.0'
    end

    ##
    # Gets the listener port
    # @return [Integer] Port for OOB listener
    def get_listener_port
      @msf_module.datastore['SRVPORT'] || 8080
    end

    ##
    # Determines if SSL should be used for target communication
    # @return [Boolean] True if SSL should be used
    def use_ssl?
      @msf_module.datastore['SSL'] || false
    end

    ##
    # Validates network configuration for OOB listener
    # @return [Array<String>] Array of network validation errors
    def validate_network_configuration
      errors = []
      
      begin
        # Check if listener port is available
        listener_host = get_listener_host
        listener_port = get_listener_port
        
        if port_in_use?(listener_host, listener_port)
          errors << "Listener port #{listener_port} is already in use on #{listener_host}"
        end
        
        # Validate that LHOST is reachable from target perspective
        lhost = @msf_module.datastore['LHOST'].to_s.strip
        if lhost == '127.0.0.1' || lhost == 'localhost'
          errors << "LHOST cannot be localhost/127.0.0.1 for OOB communication"
        end
        
      rescue => e
        @error_handler.handle_network_error(e, "network configuration validation")
        errors << "Network configuration validation failed: #{e.message}"
      end
      
      errors
    end

    ##
    # Automatically detects SSL/TLS requirement based on port and initial probe
    # Implements requirement 1.5: handle SSL/TLS automatically
    # @return [Boolean] True if SSL should be used
    def detect_ssl_requirement
      rport = @msf_module.datastore['RPORT'] || 80
      
      # Common SSL ports
      return true if [443, 8443, 9443].include?(rport)
      return false if [80, 8080, 8000, 3000].include?(rport)
      
      # For non-standard ports, try to detect by attempting connection
      begin
        rhosts = @msf_module.datastore['RHOSTS'].to_s.strip
        # Try SSL first on non-standard ports
        Timeout::timeout(5) do
          socket = TCPSocket.new(rhosts, rport)
          ssl_socket = OpenSSL::SSL::SSLSocket.new(socket)
          ssl_socket.connect
          ssl_socket.close
          socket.close
          return true
        end
      rescue
        # SSL failed, assume HTTP
        return false
      end
    end

    private

    ##
    # Validates host format (IP address or hostname)
    # @param host [String] Host to validate
    # @return [Boolean] True if valid format
    def valid_host_format?(host)
      return false if host.nil? || host.empty?
      
      # Check if it's a valid IP address
      begin
        IPAddr.new(host)
        return true
      rescue IPAddr::InvalidAddressError
        # Not an IP, check if it's a valid hostname
        return valid_hostname?(host)
      end
    end

    ##
    # Validates hostname format
    # @param hostname [String] Hostname to validate
    # @return [Boolean] True if valid hostname
    def valid_hostname?(hostname)
      return false if hostname.length > 253
      return false if hostname.empty?
      
      # Hostname can contain letters, numbers, hyphens, and dots
      hostname.match?(/\A[a-zA-Z0-9.-]+\z/) && !hostname.start_with?('-') && !hostname.end_with?('-')
    end

    ##
    # Checks if a port is already in use
    # @param host [String] Host to check
    # @param port [Integer] Port to check
    # @return [Boolean] True if port is in use
    def port_in_use?(host, port)
      begin
        Timeout::timeout(1) do
          TCPSocket.new(host, port).close
          true
        end
      rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Timeout::Error
        false
      rescue
        true # Assume in use if we can't determine
      end
    end

    ##
    # Validates HTTP response to ensure it's from a web server
    # Implements requirement 1.4: process HTTP responses correctly
    # @param response [Rex::Proto::Http::Response] HTTP response to validate
    # @return [Boolean] True if response indicates a valid web server
    def validate_http_response(response)
      return false if response.nil?
      
      # Check for valid HTTP status codes
      return false unless response.code.to_i.between?(100, 599)
      
      # Check for common web server headers
      headers = response.headers || {}
      web_server_indicators = [
        'server', 'x-powered-by', 'content-type', 'set-cookie',
        'x-frame-options', 'x-content-type-options'
      ]
      
      has_web_headers = web_server_indicators.any? { |header| headers.key?(header.downcase) }
      
      # Accept if we have web server headers or if it's a standard HTTP response
      has_web_headers || response.code.to_i.between?(200, 499)
    end

    ##
    # Fallback connectivity check without SSL
    # @return [Boolean] True if target is reachable via HTTP
    def check_connectivity_fallback
      begin
        response = @msf_module.send_request_cgi({
          'method' => 'GET',
          'uri' => @msf_module.normalize_uri(@msf_module.target_uri.path),
          'ssl' => false
        })
        
        if response && validate_http_response(response)
          @msf_module.vprint_good("Target reachable via HTTP fallback")
          return true
        end
        
        false
      rescue => e
        @msf_module.vprint_error("HTTP fallback also failed: #{e.message}")
        false
      end
    end

    def determine_protocol
      # For OOB callbacks, typically use HTTP unless specifically configured
      # The target's SSL setting doesn't affect our listener protocol
      'http'
    end
  end
end