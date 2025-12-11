# frozen_string_literal: true

require_relative 'oob_session'
require_relative 'error_handler'

module React2Shell
  ##
  # SessionManager - Manages multiple concurrent OOB sessions
  # Prevents data mixing between sessions and provides session lifecycle management
  class SessionManager
    attr_reader :active_sessions, :completed_sessions, :error_handler

    def initialize(msf_module)
      @msf_module = msf_module
      @active_sessions = {}
      @completed_sessions = {}
      @session_mutex = Mutex.new
      @error_handler = ErrorHandler.new(msf_module)
    end

    ##
    # Creates a new OOB session for a target
    # @param target_host [String] Target hostname or IP
    # @param expected_data_type [Symbol] Expected data type (:file, :command, :unknown)
    # @param source_info [String] Additional info about the data source (filename, command, etc.)
    # @return [OOBSession] The created session
    def create_session(target_host, expected_data_type = :unknown, source_info = nil)
      begin
        @session_mutex.synchronize do
          session = OOBSession.new(target_host, expected_data_type, source_info)
          @active_sessions[session.session_id] = session
          
          @msf_module.vprint_status("Created new OOB session #{session.session_id} for #{target_host} (#{expected_data_type})")
          
          session
        end
      rescue => e
        @error_handler.handle_session_error(e, "new_session", "session creation")
        raise e
      end
    end

    ##
    # Finds the appropriate session for incoming data
    # @param source_ip [String] IP address of the data source
    # @param data_content [String] Content of the received data (for analysis)
    # @return [OOBSession, nil] Matching session or nil if none found
    def find_session_for_data(source_ip, data_content = nil)
      @session_mutex.synchronize do
        # First, try to find an active session from the same source IP
        matching_sessions = @active_sessions.values.select do |session|
          session.is_active? && session_matches_source?(session, source_ip)
        end
        
        # If multiple sessions match, prefer the most recent one
        if matching_sessions.length > 1
          @msf_module.vprint_status("Multiple sessions match source #{source_ip}, using most recent")
          return matching_sessions.max_by(&:start_time)
        elsif matching_sessions.length == 1
          return matching_sessions.first
        end
        
        # If no exact match, try to find by expected data type
        if data_content
          data_type = determine_data_type_from_content(data_content)
          type_matching_sessions = @active_sessions.values.select do |session|
            session.is_active? && session.expected_data_type == data_type
          end
          
          if type_matching_sessions.length == 1
            @msf_module.vprint_status("Found session by data type match: #{data_type}")
            return type_matching_sessions.first
          end
        end
        
        # If still no match, return the oldest active session as fallback
        oldest_session = @active_sessions.values.select(&:is_active?).min_by(&:start_time)
        if oldest_session
          @msf_module.vprint_status("Using oldest active session as fallback")
        end
        
        oldest_session
      end
    end

    ##
    # Adds data to the appropriate session
    # @param source_ip [String] IP address of the data source
    # @param data [String] The received data
    # @param data_type [Symbol] Type of data (:file, :command, :error, :raw)
    # @param chunk_info [Hash] Optional chunk information for large transfers
    # @return [Boolean] True if data was successfully added to a session
    def add_data_to_session(source_ip, data, data_type = :raw, chunk_info = nil)
      begin
        session = find_session_for_data(source_ip, data)
        
        unless session
          @error_handler.handle_session_error(
            StandardError.new("No active session found for data from #{source_ip}"),
            "unknown",
            "data addition"
          )
          return false
        end
        
        success = session.add_received_data(data, source_ip, data_type, chunk_info)
        
        if success
          if chunk_info && chunk_info[:is_chunk]
            @msf_module.vprint_status("Added chunk to session #{session.session_id} (#{data.length} bytes)")
          else
            @msf_module.vprint_status("Added data to session #{session.session_id} (#{data.length} bytes)")
          end
          
          # Move completed sessions to completed list
          if session.is_complete?
            move_session_to_completed(session.session_id)
          end
        else
          @error_handler.handle_session_error(
            StandardError.new("Failed to add data to session"),
            session.session_id,
            "data addition"
          )
        end
        
        success
        
      rescue => e
        @error_handler.handle_session_error(e, "unknown", "add_data_to_session")
        false
      end
    end

    ##
    # Gets a session by ID
    # @param session_id [String] Session identifier
    # @return [OOBSession, nil] The session or nil if not found
    def get_session(session_id)
      @session_mutex.synchronize do
        @active_sessions[session_id] || @completed_sessions[session_id]
      end
    end

    ##
    # Gets all sessions (active and completed)
    # @return [Array<OOBSession>] All sessions
    def get_all_sessions
      @session_mutex.synchronize do
        (@active_sessions.values + @completed_sessions.values).sort_by(&:start_time)
      end
    end

    ##
    # Gets only active sessions
    # @return [Array<OOBSession>] Active sessions
    def get_active_sessions
      @session_mutex.synchronize do
        @active_sessions.values.select(&:is_active?)
      end
    end

    ##
    # Gets only completed sessions
    # @return [Array<OOBSession>] Completed sessions
    def get_completed_sessions
      @session_mutex.synchronize do
        @completed_sessions.values
      end
    end

    ##
    # Cleans up timed out sessions
    # @param timeout_seconds [Integer] Timeout in seconds (default: 300)
    # @return [Integer] Number of sessions cleaned up
    def cleanup_timed_out_sessions(timeout_seconds = 300)
      cleaned_count = 0
      
      @session_mutex.synchronize do
        timed_out_sessions = @active_sessions.select do |session_id, session|
          session.is_timeout?(timeout_seconds)
        end
        
        timed_out_sessions.each do |session_id, session|
          @msf_module.vprint_status("Session #{session_id} timed out, moving to completed")
          move_session_to_completed(session_id)
          cleaned_count += 1
        end
      end
      
      cleaned_count
    end

    ##
    # Cleans up all sessions and resources
    def cleanup_all_sessions
      @session_mutex.synchronize do
        (@active_sessions.values + @completed_sessions.values).each(&:cleanup)
        @active_sessions.clear
        @completed_sessions.clear
        
        @msf_module.vprint_status("Cleaned up all sessions")
      end
    end

    ##
    # Gets comprehensive error statistics from the session manager
    # @return [Hash] Error statistics and recent errors
    def get_error_statistics
      @error_handler.get_error_statistics
    end

    ##
    # Exports error log for debugging
    # @param format [Symbol] Export format (:json, :text)
    # @return [String] Formatted error log
    def export_error_log(format = :text)
      @error_handler.export_error_log(format)
    end

    ##
    # Gets session statistics
    # @return [Hash] Statistics about sessions
    def get_session_statistics
      @session_mutex.synchronize do
        {
          active_sessions: @active_sessions.length,
          completed_sessions: @completed_sessions.length,
          total_sessions: @active_sessions.length + @completed_sessions.length,
          total_bytes_received: calculate_total_bytes_received,
          oldest_active_session: @active_sessions.values.min_by(&:start_time)&.start_time,
          newest_session: (@active_sessions.values + @completed_sessions.values).max_by(&:start_time)&.start_time
        }
      end
    end

    ##
    # Checks if there are any active sessions
    # @return [Boolean] True if there are active sessions
    def has_active_sessions?
      @session_mutex.synchronize do
        @active_sessions.any? { |_, session| session.is_active? }
      end
    end

    ##
    # Waits for any session to complete or timeout
    # @param timeout_seconds [Integer] Maximum time to wait
    # @return [OOBSession, nil] Completed session or nil if timeout
    def wait_for_any_completion(timeout_seconds = 30)
      start_time = Time.now
      initial_completed_count = @completed_sessions.length
      
      while (Time.now - start_time) < timeout_seconds
        # Check if any new sessions have been completed
        @session_mutex.synchronize do
          if @completed_sessions.length > initial_completed_count
            # Return the most recently completed session
            return @completed_sessions.values.max_by(&:start_time)
          end
        end
        
        # Clean up timed out sessions
        cleanup_timed_out_sessions(timeout_seconds)
        
        # Break if no active sessions remain
        break unless has_active_sessions?
        
        sleep(0.1) # Check more frequently
      end
      
      nil
    end

    private

    ##
    # Moves a session from active to completed
    # @param session_id [String] Session ID to move
    def move_session_to_completed(session_id)
      session = @active_sessions.delete(session_id)
      if session
        @completed_sessions[session_id] = session
        @msf_module.vprint_status("Session #{session_id} moved to completed (#{session.status_description})")
      end
    end

    ##
    # Checks if a session matches a source IP
    # @param session [OOBSession] Session to check
    # @param source_ip [String] Source IP to match
    # @return [Boolean] True if session matches source
    def session_matches_source?(session, source_ip)
      # Use the session's internal validation logic
      begin
        # Create a temporary data entry to test validation
        session.send(:validate_source_ip, source_ip)
      rescue
        false
      end
    end

    ##
    # Determines data type from content analysis
    # @param content [String] Data content to analyze
    # @return [Symbol] Determined data type
    def determine_data_type_from_content(content)
      return :command if content.start_with?('CMD_OUTPUT:')
      return :file if content.start_with?('FILE_CONTENT:')
      return :error if content.start_with?('ERROR:')
      
      # Analyze content patterns
      if content.length > 1000 && content.include?("\n")
        :file
      elsif content.length < 500 && !content.include?("\n")
        :command
      else
        :raw
      end
    end

    ##
    # Calculates total bytes received across all sessions
    # @return [Integer] Total bytes received
    def calculate_total_bytes_received
      all_sessions = @active_sessions.values + @completed_sessions.values
      all_sessions.sum { |session| session.get_session_summary[:total_bytes] }
    end
  end
end