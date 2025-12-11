# frozen_string_literal: true

module React2Shell
  ##
  # ErrorHandler - Centralized error handling and logging for React2Shell
  # Provides structured error handling with descriptive messages and specific cause identification
  class ErrorHandler
    # Error categories for structured logging
    ERROR_CATEGORIES = {
      network: 'NETWORK',
      payload: 'PAYLOAD', 
      configuration: 'CONFIG',
      session: 'SESSION',
      server: 'SERVER',
      validation: 'VALIDATION',
      timeout: 'TIMEOUT',
      unknown: 'UNKNOWN'
    }.freeze

    # Error severity levels
    SEVERITY_LEVELS = {
      debug: 'DEBUG',
      info: 'INFO', 
      warning: 'WARNING',
      error: 'ERROR',
      critical: 'CRITICAL'
    }.freeze

    attr_reader :msf_module, :log_entries

    def initialize(msf_module)
      @msf_module = msf_module
      @log_entries = []
      @error_counts = Hash.new(0)
    end

    ##
    # Handles network-related errors with automatic retry logic
    # Implements requirement 4.3: automatic retry mechanism (exactly 3 attempts)
    # @param error [Exception] The network error that occurred
    # @param context [String] Context where the error occurred
    # @param retry_count [Integer] Current retry attempt number
    # @return [Hash] Error information with retry recommendations
    def handle_network_error(error, context, retry_count = 0)
      error_info = {
        category: ERROR_CATEGORIES[:network],
        severity: determine_network_error_severity(error),
        message: build_network_error_message(error, context),
        original_error: error.class.name,
        context: context,
        retry_count: retry_count,
        timestamp: Time.now,
        should_retry: should_retry_network_error?(error, retry_count),
        suggested_actions: get_network_error_suggestions(error)
      }

      log_error(error_info)
      @error_counts[:network] += 1

      # Display user-friendly error message
      case error_info[:severity]
      when SEVERITY_LEVELS[:critical]
        @msf_module.print_error(error_info[:message])
        @msf_module.print_error("Suggested actions: #{error_info[:suggested_actions].join(', ')}")
      when SEVERITY_LEVELS[:error]
        @msf_module.print_error(error_info[:message])
        if error_info[:should_retry] && retry_count < 3
          @msf_module.print_status("Will retry in #{calculate_retry_delay(retry_count)} seconds (attempt #{retry_count + 1}/3)")
        end
      when SEVERITY_LEVELS[:warning]
        @msf_module.print_warning(error_info[:message])
      end

      error_info
    end

    ##
    # Handles payload generation errors with specific cause identification
    # Implements requirement 7.2: show exactly what parameter caused the problem
    # @param error [Exception] The payload generation error
    # @param payload_type [Symbol] Type of payload being generated
    # @param parameters [Hash] Parameters used in payload generation
    # @return [Hash] Error information with parameter-specific details
    def handle_payload_error(error, payload_type, parameters = {})
      error_info = {
        category: ERROR_CATEGORIES[:payload],
        severity: SEVERITY_LEVELS[:error],
        message: build_payload_error_message(error, payload_type, parameters),
        original_error: error.class.name,
        payload_type: payload_type,
        parameters: sanitize_parameters(parameters),
        timestamp: Time.now,
        problematic_parameter: identify_problematic_parameter(error, parameters),
        suggested_fix: get_payload_error_fix(error, payload_type, parameters)
      }

      log_error(error_info)
      @error_counts[:payload] += 1

      # Display detailed error information
      @msf_module.print_error(error_info[:message])
      if error_info[:problematic_parameter]
        @msf_module.print_error("Problematic parameter: #{error_info[:problematic_parameter]}")
      end
      if error_info[:suggested_fix]
        @msf_module.print_status("Suggested fix: #{error_info[:suggested_fix]}")
      end

      error_info
    end

    ##
    # Handles configuration validation errors
    # Implements requirement 7.1: descriptive error messages
    # @param validation_errors [Array<String>] List of validation errors
    # @param context [String] Configuration context
    # @return [Hash] Error information with validation details
    def handle_configuration_error(validation_errors, context = 'configuration')
      error_info = {
        category: ERROR_CATEGORIES[:configuration],
        severity: SEVERITY_LEVELS[:error],
        message: build_configuration_error_message(validation_errors, context),
        validation_errors: validation_errors,
        context: context,
        timestamp: Time.now,
        suggested_actions: get_configuration_error_suggestions(validation_errors)
      }

      log_error(error_info)
      @error_counts[:configuration] += 1

      # Display configuration errors with suggestions
      @msf_module.print_error(error_info[:message])
      validation_errors.each_with_index do |error, index|
        @msf_module.print_error("  #{index + 1}. #{error}")
      end
      
      if error_info[:suggested_actions].any?
        @msf_module.print_status("Suggested actions:")
        error_info[:suggested_actions].each_with_index do |action, index|
          @msf_module.print_status("  #{index + 1}. #{action}")
        end
      end

      error_info
    end

    ##
    # Handles session management errors
    # @param error [Exception] The session error
    # @param session_id [String] Session identifier
    # @param operation [String] Operation being performed
    # @return [Hash] Error information with session details
    def handle_session_error(error, session_id, operation)
      error_info = {
        category: ERROR_CATEGORIES[:session],
        severity: determine_session_error_severity(error),
        message: build_session_error_message(error, session_id, operation),
        original_error: error.class.name,
        session_id: session_id,
        operation: operation,
        timestamp: Time.now,
        recovery_actions: get_session_recovery_actions(error, operation)
      }

      log_error(error_info)
      @error_counts[:session] += 1

      # Display session error with recovery suggestions
      case error_info[:severity]
      when SEVERITY_LEVELS[:error]
        @msf_module.print_error(error_info[:message])
      when SEVERITY_LEVELS[:warning]
        @msf_module.print_warning(error_info[:message])
      end

      if error_info[:recovery_actions].any?
        @msf_module.print_status("Recovery actions: #{error_info[:recovery_actions].join(', ')}")
      end

      error_info
    end

    ##
    # Handles server operation errors (OOB listener)
    # @param error [Exception] The server error
    # @param server_context [String] Server operation context
    # @param client_info [String] Client information if available
    # @return [Hash] Error information with server details
    def handle_server_error(error, server_context, client_info = nil)
      error_info = {
        category: ERROR_CATEGORIES[:server],
        severity: determine_server_error_severity(error),
        message: build_server_error_message(error, server_context, client_info),
        original_error: error.class.name,
        server_context: server_context,
        client_info: client_info,
        timestamp: Time.now,
        is_recoverable: is_server_error_recoverable?(error),
        suggested_actions: get_server_error_suggestions(error, server_context)
      }

      log_error(error_info)
      @error_counts[:server] += 1

      # Display server error with appropriate severity
      case error_info[:severity]
      when SEVERITY_LEVELS[:critical]
        @msf_module.print_error(error_info[:message])
        @msf_module.print_error("Server operation cannot continue")
      when SEVERITY_LEVELS[:error]
        @msf_module.print_error(error_info[:message])
      when SEVERITY_LEVELS[:warning]
        @msf_module.print_warning(error_info[:message])
      end

      if error_info[:suggested_actions].any?
        @msf_module.print_status("Suggested actions: #{error_info[:suggested_actions].join(', ')}")
      end

      error_info
    end

    ##
    # Handles timeout errors with context-specific suggestions
    # @param operation [String] Operation that timed out
    # @param timeout_duration [Integer] Timeout duration in seconds
    # @param context [Hash] Additional context information
    # @return [Hash] Error information with timeout details
    def handle_timeout_error(operation, timeout_duration, context = {})
      error_info = {
        category: ERROR_CATEGORIES[:timeout],
        severity: SEVERITY_LEVELS[:warning],
        message: build_timeout_error_message(operation, timeout_duration, context),
        operation: operation,
        timeout_duration: timeout_duration,
        context: context,
        timestamp: Time.now,
        suggested_actions: get_timeout_error_suggestions(operation, context)
      }

      log_error(error_info)
      @error_counts[:timeout] += 1

      # Display timeout information
      @msf_module.print_warning(error_info[:message])
      if error_info[:suggested_actions].any?
        @msf_module.print_status("Suggestions: #{error_info[:suggested_actions].join(', ')}")
      end

      error_info
    end

    ##
    # Logs structured error information for debugging and analysis
    # @param error_info [Hash] Structured error information
    def log_error(error_info)
      @log_entries << error_info

      # Log to Metasploit's verbose output for debugging
      if @msf_module.datastore['VERBOSE']
        @msf_module.vprint_status("ERROR LOG: #{error_info[:category]} - #{error_info[:message]}")
        @msf_module.vprint_status("  Timestamp: #{error_info[:timestamp]}")
        @msf_module.vprint_status("  Context: #{error_info[:context] || 'N/A'}")
        if error_info[:original_error]
          @msf_module.vprint_status("  Original Error: #{error_info[:original_error]}")
        end
      end
    end

    ##
    # Gets error statistics for analysis
    # @return [Hash] Error statistics by category and severity
    def get_error_statistics
      {
        total_errors: @log_entries.length,
        by_category: @error_counts.dup,
        by_severity: @log_entries.group_by { |e| e[:severity] }.transform_values(&:count),
        recent_errors: @log_entries.last(5),
        first_error_time: @log_entries.first&.dig(:timestamp),
        last_error_time: @log_entries.last&.dig(:timestamp)
      }
    end

    ##
    # Clears error log (useful for testing or reset)
    def clear_error_log
      @log_entries.clear
      @error_counts.clear
    end

    ##
    # Exports error log for external analysis
    # @param format [Symbol] Export format (:json, :text)
    # @return [String] Formatted error log
    def export_error_log(format = :text)
      case format
      when :json
        require 'json'
        {
          statistics: get_error_statistics,
          entries: @log_entries
        }.to_json
      when :text
        export_text_log
      else
        raise ArgumentError, "Unsupported export format: #{format}"
      end
    end

    private

    ##
    # Determines severity level for network errors
    def determine_network_error_severity(error)
      case error.class.name
      when /ConnectionRefused/, /HostUnreach/
        SEVERITY_LEVELS[:critical]
      when /Timeout/, /ConnectionTimeout/
        SEVERITY_LEVELS[:error]
      when /ConnectionReset/, /BrokenPipe/
        SEVERITY_LEVELS[:warning]
      else
        SEVERITY_LEVELS[:error]
      end
    end

    ##
    # Builds descriptive network error messages
    def build_network_error_message(error, context)
      base_message = case error.class.name
      when /ConnectionRefused/
        "Connection refused by target server"
      when /HostUnreach/, /NetworkUnreach/
        "Target host is unreachable"
      when /Timeout/, /ConnectionTimeout/
        "Connection timed out"
      when /ConnectionReset/
        "Connection was reset by target"
      when /SSLError/
        "SSL/TLS connection failed"
      when /SocketError/
        "Network socket error occurred"
      else
        "Network communication failed"
      end

      "#{base_message} during #{context}: #{error.message}"
    end

    ##
    # Determines if network error should be retried
    def should_retry_network_error?(error, retry_count)
      return false if retry_count >= 3

      retryable_errors = [
        /Timeout/,
        /ConnectionReset/,
        /TemporaryFailure/,
        /ServiceUnavailable/
      ]

      retryable_errors.any? { |pattern| error.class.name =~ pattern }
    end

    ##
    # Gets network error suggestions
    def get_network_error_suggestions(error)
      suggestions = []

      case error.class.name
      when /ConnectionRefused/
        suggestions << "Verify target service is running"
        suggestions << "Check firewall settings"
        suggestions << "Confirm correct port number"
      when /HostUnreach/
        suggestions << "Verify target IP address"
        suggestions << "Check network connectivity"
        suggestions << "Confirm routing configuration"
      when /Timeout/
        suggestions << "Increase HTTP_DELAY timeout"
        suggestions << "Check network latency"
        suggestions << "Verify target is responsive"
      when /SSLError/
        suggestions << "Try disabling SSL (set SSL=false)"
        suggestions << "Verify SSL certificate validity"
        suggestions << "Check SSL/TLS version compatibility"
      end

      suggestions << "Enable verbose mode for more details" if suggestions.empty?
      suggestions
    end

    ##
    # Calculates retry delay with exponential backoff
    def calculate_retry_delay(retry_count)
      [1, 2, 4][retry_count] || 4
    end

    ##
    # Builds payload error messages with parameter details
    def build_payload_error_message(error, payload_type, parameters)
      "Failed to generate #{payload_type} payload: #{error.message}"
    end

    ##
    # Identifies which parameter caused the payload error
    def identify_problematic_parameter(error, parameters)
      # Analyze error message for parameter names
      parameters.keys.find do |param|
        error.message.include?(param.to_s) || error.message.include?(parameters[param].to_s)
      end
    end

    ##
    # Gets payload error fix suggestions
    def get_payload_error_fix(error, payload_type, parameters)
      case error.class.name
      when /ArgumentError/
        "Check parameter format and ensure all required parameters are provided"
      when /EncodingError/
        "Verify parameter encoding and escape special characters"
      when /SyntaxError/
        "Check for invalid characters in command or filepath parameters"
      else
        "Validate all payload parameters and try again"
      end
    end

    ##
    # Sanitizes parameters for logging (removes sensitive data)
    def sanitize_parameters(parameters)
      sanitized = parameters.dup
      sensitive_keys = [:password, :token, :key, :secret]
      
      sensitive_keys.each do |key|
        if sanitized.key?(key)
          sanitized[key] = '[REDACTED]'
        end
      end
      
      sanitized
    end

    ##
    # Builds configuration error messages
    def build_configuration_error_message(validation_errors, context)
      "Configuration validation failed for #{context} (#{validation_errors.length} errors)"
    end

    ##
    # Gets configuration error suggestions
    def get_configuration_error_suggestions(validation_errors)
      suggestions = []

      validation_errors.each do |error|
        case error
        when /RHOSTS/
          suggestions << "Set RHOSTS to target IP or hostname"
        when /LHOST/
          suggestions << "Set LHOST to your IP address (not localhost)"
        when /port.*in use/
          suggestions << "Choose a different SRVPORT value"
        when /FILEPATH.*CMD/
          suggestions << "Specify either FILEPATH or CMD, not both"
        when /SSL/
          suggestions << "Check SSL configuration or let auto-detection handle it"
        end
      end

      suggestions.uniq
    end

    ##
    # Determines session error severity
    def determine_session_error_severity(error)
      case error.class.name
      when /ArgumentError/, /ValidationError/
        SEVERITY_LEVELS[:error]
      when /TimeoutError/
        SEVERITY_LEVELS[:warning]
      else
        SEVERITY_LEVELS[:error]
      end
    end

    ##
    # Builds session error messages
    def build_session_error_message(error, session_id, operation)
      "Session #{session_id} error during #{operation}: #{error.message}"
    end

    ##
    # Gets session recovery actions
    def get_session_recovery_actions(error, operation)
      actions = []

      case operation
      when /create/
        actions << "Retry session creation"
        actions << "Check target connectivity"
      when /data/
        actions << "Verify data format"
        actions << "Check session timeout settings"
      when /cleanup/
        actions << "Manual cleanup may be required"
      end

      actions
    end

    ##
    # Determines server error severity
    def determine_server_error_severity(error)
      case error.class.name
      when /AddressInUse/
        SEVERITY_LEVELS[:critical]
      when /PermissionDenied/
        SEVERITY_LEVELS[:critical]
      when /ConnectionError/
        SEVERITY_LEVELS[:warning]
      else
        SEVERITY_LEVELS[:error]
      end
    end

    ##
    # Builds server error messages
    def build_server_error_message(error, server_context, client_info)
      message = "Server error in #{server_context}: #{error.message}"
      message += " (client: #{client_info})" if client_info
      message
    end

    ##
    # Checks if server error is recoverable
    def is_server_error_recoverable?(error)
      recoverable_errors = [
        /ConnectionReset/,
        /BrokenPipe/,
        /Timeout/
      ]

      recoverable_errors.any? { |pattern| error.class.name =~ pattern }
    end

    ##
    # Gets server error suggestions
    def get_server_error_suggestions(error, server_context)
      suggestions = []

      case error.class.name
      when /AddressInUse/
        suggestions << "Choose a different SRVPORT"
        suggestions << "Stop other services using the port"
      when /PermissionDenied/
        suggestions << "Use a port number above 1024"
        suggestions << "Run with appropriate privileges"
      when /ConnectionError/
        suggestions << "Check client network connectivity"
        suggestions << "Verify firewall settings"
      end

      suggestions
    end

    ##
    # Builds timeout error messages
    def build_timeout_error_message(operation, timeout_duration, context)
      "Operation '#{operation}' timed out after #{timeout_duration} seconds"
    end

    ##
    # Gets timeout error suggestions
    def get_timeout_error_suggestions(operation, context)
      suggestions = []

      case operation
      when /connectivity/, /connection/
        suggestions << "Increase HTTP_DELAY timeout"
        suggestions << "Check network latency to target"
      when /oob/, /callback/
        suggestions << "Verify target can reach your LHOST"
        suggestions << "Check firewall blocking OOB connections"
      when /session/
        suggestions << "Target may not be vulnerable"
        suggestions << "Verify payload executed successfully"
      end

      suggestions << "Enable verbose mode for more details" if suggestions.empty?
      suggestions
    end

    ##
    # Exports error log in text format
    def export_text_log
      output = []
      output << "React2Shell Error Log"
      output << "=" * 50
      output << ""

      stats = get_error_statistics
      output << "Statistics:"
      output << "  Total Errors: #{stats[:total_errors]}"
      output << "  By Category: #{stats[:by_category]}"
      output << "  By Severity: #{stats[:by_severity]}"
      output << ""

      output << "Error Entries:"
      output << "-" * 30

      @log_entries.each_with_index do |entry, index|
        output << "#{index + 1}. [#{entry[:timestamp]}] #{entry[:category]} - #{entry[:severity]}"
        output << "   #{entry[:message]}"
        output << "   Context: #{entry[:context]}" if entry[:context]
        output << ""
      end

      output.join("\n")
    end
  end
end