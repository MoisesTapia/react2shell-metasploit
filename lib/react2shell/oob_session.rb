# frozen_string_literal: true

require 'securerandom'
require 'time'

module React2Shell
  ##
  # OOBSession - Manages individual Out-of-Band exploit sessions
  # Handles concurrent sessions with unique identifiers and prevents data mixing
  class OOBSession
    attr_accessor :session_id, :target_host, :start_time, :received_data, :status
    attr_reader :expected_data_type, :source_info

    # Session status constants
    STATUS_WAITING = :waiting
    STATUS_RECEIVING = :receiving
    STATUS_COMPLETE = :complete
    STATUS_TIMEOUT = :timeout
    STATUS_ERROR = :error

    def initialize(target_host, expected_data_type = :unknown, source_info = nil)
      @session_id = SecureRandom.hex(8)
      @target_host = target_host
      @start_time = Time.now
      @received_data = []
      @status = STATUS_WAITING
      @expected_data_type = expected_data_type
      @source_info = source_info
      @last_activity = Time.now
      @total_bytes_received = 0
    end

    ##
    # Adds received data with metadata and source validation
    # Supports large data handling and chunked transfers
    # @param data [String] The received data content
    # @param source_ip [String] IP address of the data source
    # @param data_type [Symbol] Type of data (:file, :command, :error, :raw)
    # @param chunk_info [Hash] Optional chunk information for large transfers
    # @return [Boolean] True if data was accepted, false if rejected
    def add_received_data(data, source_ip, data_type = :raw, chunk_info = nil)
      # Validate that data comes from the expected target
      unless validate_source_ip(source_ip)
        return false
      end

      # Update session status
      @status = STATUS_RECEIVING if @status == STATUS_WAITING
      @last_activity = Time.now

      # Handle large data transfers with chunking
      if chunk_info && chunk_info[:is_chunk]
        return handle_chunked_data(data, source_ip, data_type, chunk_info)
      end

      # Verify data integrity for large transfers
      if data.length > 1024 * 1024  # 1MB threshold
        unless verify_large_data_integrity(data)
          @status = STATUS_ERROR
          @error_message = "Large data integrity verification failed"
          return false
        end
      end

      # Create data entry with metadata
      data_entry = {
        content: data,
        source_ip: source_ip,
        data_type: data_type,
        timestamp: Time.now,
        size: data.length,
        sequence: @received_data.length + 1,
        is_large_data: data.length > 1024 * 1024,
        checksum: calculate_data_checksum(data)
      }

      @received_data << data_entry
      @total_bytes_received += data.length

      # Log large data reception
      if data.length > 1024 * 1024
        puts "Session #{@session_id}: Received large data chunk: #{data.length} bytes"
      end

      # Check if session is complete based on data type and content
      if should_mark_complete?(data, data_type)
        @status = STATUS_COMPLETE
      end

      true
    end

    ##
    # Determines if the session has received all expected data
    # @return [Boolean] True if session is complete
    def is_complete?
      @status == STATUS_COMPLETE
    end

    ##
    # Checks if the session has timed out
    # @param timeout_seconds [Integer] Timeout in seconds (default: 300)
    # @return [Boolean] True if session has timed out
    def is_timeout?(timeout_seconds = 300)
      return false if is_complete?
      
      time_since_start = Time.now - @start_time
      time_since_activity = Time.now - @last_activity
      
      # Timeout if no activity for the specified time or total time exceeds limit
      if time_since_activity > timeout_seconds || time_since_start > (timeout_seconds * 2)
        @status = STATUS_TIMEOUT unless is_complete?
        return true
      end
      
      false
    end

    ##
    # Marks the session as having an error
    # @param error_message [String] Description of the error
    def mark_error(error_message)
      @status = STATUS_ERROR
      @error_message = error_message
      @last_activity = Time.now
    end

    ##
    # Gets all received data concatenated
    # @return [String] All received data content
    def get_all_data
      @received_data.map { |entry| entry[:content] }.join
    end

    ##
    # Gets received data with full metadata
    # @return [Array<Hash>] Array of data entries with metadata
    def get_data_with_metadata
      @received_data.dup
    end

    ##
    # Gets the latest received data entry
    # @return [Hash, nil] Latest data entry or nil if no data
    def get_latest_data
      @received_data.last
    end

    ##
    # Gets session summary information
    # @return [Hash] Session summary with key metrics
    def get_session_summary
      {
        session_id: @session_id,
        target_host: @target_host,
        status: @status,
        start_time: @start_time,
        last_activity: @last_activity,
        duration: Time.now - @start_time,
        data_entries: @received_data.length,
        total_bytes: @total_bytes_received,
        expected_type: @expected_data_type,
        source_info: @source_info,
        error_message: @error_message
      }
    end

    ##
    # Checks if session is active (not complete, timeout, or error)
    # @return [Boolean] True if session is still active
    def is_active?
      [STATUS_WAITING, STATUS_RECEIVING].include?(@status)
    end

    ##
    # Cleans up session resources
    def cleanup
      @received_data.clear
      @status = STATUS_COMPLETE unless @status == STATUS_ERROR
    end

    ##
    # Gets a human-readable status description
    # @return [String] Status description
    def status_description
      case @status
      when STATUS_WAITING
        "Waiting for data"
      when STATUS_RECEIVING
        "Receiving data (#{@received_data.length} entries, #{@total_bytes_received} bytes)"
      when STATUS_COMPLETE
        "Complete (#{@received_data.length} entries, #{@total_bytes_received} bytes)"
      when STATUS_TIMEOUT
        "Timed out after #{(Time.now - @start_time).round(1)} seconds"
      when STATUS_ERROR
        "Error: #{@error_message}"
      else
        "Unknown status: #{@status}"
      end
    end

    ##
    # Handles chunked data transfers for large files/outputs
    # @param data [String] Chunk data
    # @param source_ip [String] Source IP address
    # @param data_type [Symbol] Type of data
    # @param chunk_info [Hash] Chunk metadata (index, total_chunks, chunk_id)
    # @return [Boolean] True if chunk was processed successfully
    def handle_chunked_data(data, source_ip, data_type, chunk_info)
      @chunked_data ||= {}
      chunk_id = chunk_info[:chunk_id] || 'default'
      
      # Initialize chunk session if not exists
      unless @chunked_data[chunk_id]
        @chunked_data[chunk_id] = {
          chunks: Array.new(chunk_info[:total_chunks]),
          received_count: 0,
          total_chunks: chunk_info[:total_chunks],
          data_type: data_type,
          start_time: Time.now,
          expected_size: chunk_info[:expected_size]
        }
      end
      
      chunk_session = @chunked_data[chunk_id]
      chunk_index = chunk_info[:chunk_index]
      
      # Validate chunk index
      if chunk_index < 0 || chunk_index >= chunk_session[:total_chunks]
        @error_message = "Invalid chunk index: #{chunk_index}"
        return false
      end
      
      # Store chunk if not already received
      if chunk_session[:chunks][chunk_index].nil?
        # Verify chunk integrity
        unless verify_chunk_integrity(data, chunk_index)
          @error_message = "Chunk #{chunk_index} integrity verification failed"
          return false
        end
        
        chunk_session[:chunks][chunk_index] = {
          data: data,
          timestamp: Time.now,
          size: data.length,
          checksum: calculate_data_checksum(data)
        }
        chunk_session[:received_count] += 1
        
        puts "Session #{@session_id}: Received chunk #{chunk_index + 1}/#{chunk_session[:total_chunks]} (#{data.length} bytes)"
      end
      
      # Check if all chunks received
      if chunk_session[:received_count] == chunk_session[:total_chunks]
        # Reassemble complete data
        complete_data = reassemble_chunked_data(chunk_session)
        if complete_data
          # Add reassembled data as regular data entry
          data_entry = {
            content: complete_data,
            source_ip: source_ip,
            data_type: data_type,
            timestamp: Time.now,
            size: complete_data.length,
            sequence: @received_data.length + 1,
            is_reassembled: true,
            chunk_count: chunk_session[:total_chunks],
            checksum: calculate_data_checksum(complete_data)
          }
          
          @received_data << data_entry
          @total_bytes_received += complete_data.length
          
          # Clean up chunk session
          @chunked_data.delete(chunk_id)
          
          puts "Session #{@session_id}: Reassembled complete data: #{complete_data.length} bytes from #{chunk_session[:total_chunks]} chunks"
          
          # Check if session is complete
          if should_mark_complete?(complete_data, data_type)
            @status = STATUS_COMPLETE
          end
          
          return true
        else
          @status = STATUS_ERROR
          @error_message = "Failed to reassemble chunked data"
          return false
        end
      end
      
      true
    end

    ##
    # Reassembles chunked data into complete content
    # @param chunk_session [Hash] Chunk session data
    # @return [String, nil] Reassembled data or nil if failed
    def reassemble_chunked_data(chunk_session)
      # Verify all chunks are present
      if chunk_session[:chunks].any?(&:nil?)
        puts "Missing chunks detected during reassembly"
        return nil
      end
      
      # Reassemble data
      complete_data = chunk_session[:chunks].map { |chunk| chunk[:data] }.join
      
      # Verify expected size if provided
      if chunk_session[:expected_size] && complete_data.length != chunk_session[:expected_size]
        puts "Reassembled data size mismatch: expected #{chunk_session[:expected_size]}, got #{complete_data.length}"
        return nil
      end
      
      # Verify reassembled data integrity
      unless verify_large_data_integrity(complete_data)
        puts "Reassembled data integrity verification failed"
        return nil
      end
      
      complete_data
    end

    ##
    # Verifies integrity of large data transfers
    # @param data [String] Data to verify
    # @return [Boolean] True if data appears valid
    def verify_large_data_integrity(data)
      return false if data.nil?
      return true if data.length < 1024  # Skip verification for small data
      
      # Check for corruption indicators
      # Look for excessive null bytes (might indicate corruption)
      null_byte_ratio = data.count("\x00").to_f / data.length
      if null_byte_ratio > 0.5
        puts "High null byte ratio detected: #{(null_byte_ratio * 100).round(2)}%"
        return false
      end
      
      # Check for reasonable character distribution
      unique_chars = data.chars.uniq.length
      if unique_chars < 5 && data.length > 10000
        puts "Low character diversity detected: #{unique_chars} unique characters in #{data.length} bytes"
        return false
      end
      
      true
    end

    ##
    # Verifies integrity of individual chunks
    # @param chunk_data [String] Chunk data to verify
    # @param chunk_index [Integer] Index of the chunk
    # @return [Boolean] True if chunk appears valid
    def verify_chunk_integrity(chunk_data, chunk_index)
      return false if chunk_data.nil?
      return true if chunk_data.empty?  # Empty chunks might be valid
      
      # Check for reasonable chunk size
      if chunk_data.length > 50 * 1024 * 1024  # 50MB per chunk is excessive
        puts "Chunk #{chunk_index} is unusually large: #{chunk_data.length} bytes"
        return false
      end
      
      true
    end

    ##
    # Calculates a simple checksum for data integrity verification
    # @param data [String] Data to checksum
    # @return [String] Hexadecimal checksum
    def calculate_data_checksum(data)
      return '0' if data.nil? || data.empty?
      
      # Simple CRC32-like checksum
      checksum = 0
      data.each_byte do |byte|
        checksum = ((checksum << 1) ^ byte) & 0xFFFFFFFF
      end
      
      checksum.to_s(16)
    end

    ##
    # Gets statistics about chunked data transfers
    # @return [Hash] Chunked data statistics
    def get_chunked_data_statistics
      return {} unless @chunked_data
      
      stats = {}
      @chunked_data.each do |chunk_id, session|
        stats[chunk_id] = {
          received_chunks: session[:received_count],
          total_chunks: session[:total_chunks],
          progress: (session[:received_count].to_f / session[:total_chunks] * 100).round(2),
          elapsed_time: Time.now - session[:start_time],
          data_type: session[:data_type]
        }
      end
      
      stats
    end

    private

    ##
    # Validates that the source IP matches the expected target
    # @param source_ip [String] IP address to validate
    # @return [Boolean] True if source is valid
    def validate_source_ip(source_ip)
      return true if @target_host.nil? || @target_host.empty?
      
      # Handle different target host formats
      target_ips = resolve_target_ips(@target_host)
      
      # Allow data from any of the resolved IPs
      target_ips.include?(source_ip) || source_ip == '127.0.0.1' || source_ip == '::1'
    end

    ##
    # Resolves target host to possible IP addresses
    # @param target_host [String] Target hostname or IP
    # @return [Array<String>] Array of possible IP addresses
    def resolve_target_ips(target_host)
      ips = [target_host]
      
      # If it's already an IP, return it
      if target_host =~ /^\d+\.\d+\.\d+\.\d+$/
        return ips
      end
      
      # Try to resolve hostname to IP
      begin
        require 'resolv'
        resolved_ips = Resolv.getaddresses(target_host)
        ips.concat(resolved_ips)
      rescue => e
        # If resolution fails, just use the original target
      end
      
      ips.uniq
    end

    ##
    # Determines if session should be marked complete based on received data
    # @param data [String] The received data
    # @param data_type [Symbol] Type of data received
    # @return [Boolean] True if session should be marked complete
    def should_mark_complete?(data, data_type)
      # For command execution, consider complete when we receive output or error
      if @expected_data_type == :command && [:command, :error].include?(data_type)
        return true
      end
      
      # For file exfiltration, consider complete when we receive file content
      if @expected_data_type == :file && data_type == :file
        return true
      end
      
      # For unknown types, consider complete after first data reception
      if @expected_data_type == :unknown && !data.nil? && !data.empty?
        return true
      end
      
      # Check for explicit completion markers in the data
      if data.include?('REACT2SHELL_COMPLETE') || data.include?('END_OF_DATA')
        return true
      end
      
      false
    end
  end
end