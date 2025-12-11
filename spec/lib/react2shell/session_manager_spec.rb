# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../lib/react2shell/session_manager'

RSpec.describe React2Shell::SessionManager do
  let(:mock_module) { create_mock_msf_module }
  let(:manager) { described_class.new(mock_module) }
  let(:target_host) { '192.168.1.100' }

  describe '#initialize' do
    it 'initializes with empty session collections' do
      expect(manager.active_sessions).to be_empty
      expect(manager.completed_sessions).to be_empty
    end
  end

  describe '#create_session' do
    it 'creates and stores a new session' do
      session = manager.create_session(target_host, :command, 'test cmd')
      
      expect(session).to be_a(React2Shell::OOBSession)
      expect(session.target_host).to eq(target_host)
      expect(session.expected_data_type).to eq(:command)
      expect(session.source_info).to eq('test cmd')
      expect(manager.active_sessions).to have_key(session.session_id)
    end

    it 'creates sessions with unique IDs' do
      session1 = manager.create_session(target_host)
      session2 = manager.create_session(target_host)
      
      expect(session1.session_id).not_to eq(session2.session_id)
      expect(manager.active_sessions.length).to eq(2)
    end
  end

  describe '#find_session_for_data' do
    let!(:session1) { manager.create_session(target_host, :command, 'cmd1') }
    let!(:session2) { manager.create_session('192.168.1.101', :file, 'file1') }

    it 'finds session by matching source IP' do
      found_session = manager.find_session_for_data(target_host)
      expect(found_session).to eq(session1)
    end

    it 'finds session by data type when IP does not match exactly' do
      found_session = manager.find_session_for_data('192.168.1.102', 'CMD_OUTPUT:result')
      expect(found_session).to eq(session1)
    end

    it 'returns most recent session when multiple match' do
      session3 = manager.create_session(target_host, :command, 'cmd2')
      sleep(0.01) # Ensure different timestamps
      
      found_session = manager.find_session_for_data(target_host)
      expect(found_session).to eq(session3)
    end

    it 'returns oldest active session as fallback' do
      found_session = manager.find_session_for_data('10.0.0.1')
      expect(found_session).to eq(session1) # Oldest session
    end

    it 'returns nil when no sessions exist' do
      manager.cleanup_all_sessions
      expect(manager.find_session_for_data('10.0.0.1')).to be_nil
    end
  end

  describe '#add_data_to_session' do
    let!(:session) { manager.create_session(target_host, :command, 'test cmd') }

    it 'adds data to appropriate session' do
      result = manager.add_data_to_session(target_host, 'output data', :command)
      
      expect(result).to be true
      expect(session.get_all_data).to eq('output data')
    end

    it 'moves completed sessions to completed list' do
      manager.add_data_to_session(target_host, 'output data', :command)
      
      expect(manager.active_sessions).to be_empty
      expect(manager.completed_sessions).to have_key(session.session_id)
    end

    it 'returns false when no session found' do
      manager.cleanup_all_sessions
      result = manager.add_data_to_session('10.0.0.1', 'data', :raw)
      
      expect(result).to be false
    end
  end

  describe '#get_session' do
    let!(:session) { manager.create_session(target_host, :command, 'test') }

    it 'retrieves active session by ID' do
      found = manager.get_session(session.session_id)
      expect(found).to eq(session)
    end

    it 'retrieves completed session by ID' do
      manager.add_data_to_session(target_host, 'data', :command)
      
      found = manager.get_session(session.session_id)
      expect(found).to eq(session)
    end

    it 'returns nil for non-existent session' do
      expect(manager.get_session('nonexistent')).to be_nil
    end
  end

  describe '#get_all_sessions' do
    it 'returns all sessions sorted by start time' do
      session1 = manager.create_session(target_host, :command, 'cmd1')
      sleep(0.01)
      session2 = manager.create_session(target_host, :file, 'file1')
      
      # Complete one session
      manager.add_data_to_session(target_host, 'data', :command)
      
      all_sessions = manager.get_all_sessions
      expect(all_sessions.length).to eq(2)
      expect(all_sessions.first).to eq(session1) # Oldest first
      expect(all_sessions.last).to eq(session2)
    end
  end

  describe '#get_active_sessions' do
    it 'returns only active sessions' do
      session1 = manager.create_session(target_host, :command, 'cmd1')
      session2 = manager.create_session('192.168.1.101', :file, 'file1')
      
      # Complete one session by adding command data to the command session
      manager.add_data_to_session(target_host, 'data', :command)
      
      active = manager.get_active_sessions
      expect(active.length).to eq(1)
      expect(active.first).to eq(session2)
    end
  end

  describe '#get_completed_sessions' do
    it 'returns only completed sessions' do
      session1 = manager.create_session(target_host, :command, 'cmd1')
      session2 = manager.create_session('192.168.1.101', :file, 'file1')
      
      # Complete one session by adding command data to the command session
      manager.add_data_to_session(target_host, 'data', :command)
      
      completed = manager.get_completed_sessions
      expect(completed.length).to eq(1)
      expect(completed.first).to eq(session1)
    end
  end

  describe '#cleanup_timed_out_sessions' do
    it 'moves timed out sessions to completed' do
      session = manager.create_session(target_host, :command, 'cmd')
      
      # Simulate timeout by setting old timestamps
      session.instance_variable_set(:@start_time, Time.now - 400)
      session.instance_variable_set(:@last_activity, Time.now - 400)
      
      cleaned = manager.cleanup_timed_out_sessions(300)
      
      expect(cleaned).to eq(1)
      expect(manager.active_sessions).to be_empty
      expect(manager.completed_sessions).to have_key(session.session_id)
    end

    it 'does not timeout recent sessions' do
      session = manager.create_session(target_host, :command, 'cmd')
      
      cleaned = manager.cleanup_timed_out_sessions(300)
      
      expect(cleaned).to eq(0)
      expect(manager.active_sessions).to have_key(session.session_id)
    end
  end

  describe '#cleanup_all_sessions' do
    it 'clears all sessions and calls cleanup on each' do
      session1 = manager.create_session(target_host, :command, 'cmd1')
      session2 = manager.create_session(target_host, :file, 'file1')
      
      expect(session1).to receive(:cleanup)
      expect(session2).to receive(:cleanup)
      
      manager.cleanup_all_sessions
      
      expect(manager.active_sessions).to be_empty
      expect(manager.completed_sessions).to be_empty
    end
  end

  describe '#get_session_statistics' do
    it 'returns comprehensive statistics' do
      session1 = manager.create_session(target_host, :command, 'cmd1')
      session2 = manager.create_session('192.168.1.101', :file, 'file1')
      
      # Add some data and complete one session
      manager.add_data_to_session(target_host, 'test data', :command)
      
      stats = manager.get_session_statistics
      
      expect(stats[:active_sessions]).to eq(1)
      expect(stats[:completed_sessions]).to eq(1)
      expect(stats[:total_sessions]).to eq(2)
      expect(stats[:total_bytes_received]).to be > 0
      expect(stats[:oldest_active_session]).to be_a(Time)
      expect(stats[:newest_session]).to be_a(Time)
    end
  end

  describe '#has_active_sessions?' do
    it 'returns false when no sessions exist' do
      expect(manager.has_active_sessions?).to be false
    end

    it 'returns true when active sessions exist' do
      manager.create_session(target_host, :command, 'cmd')
      expect(manager.has_active_sessions?).to be true
    end

    it 'returns false when only completed sessions exist' do
      manager.create_session(target_host, :command, 'cmd')
      manager.add_data_to_session(target_host, 'data', :command)
      
      expect(manager.has_active_sessions?).to be false
    end
  end

  describe '#wait_for_any_completion' do
    it 'returns completed session when one completes' do
      session = manager.create_session(target_host, :command, 'cmd')
      
      # Simulate completion in a separate thread
      Thread.new do
        sleep(0.1)
        manager.add_data_to_session(target_host, 'data', :command)
      end
      
      completed = manager.wait_for_any_completion(2)
      expect(completed).to eq(session)
    end

    it 'returns nil on timeout' do
      manager.create_session(target_host, :command, 'cmd')
      
      completed = manager.wait_for_any_completion(0.1)
      expect(completed).to be_nil
    end

    it 'returns nil when no active sessions' do
      completed = manager.wait_for_any_completion(1)
      expect(completed).to be_nil
    end
  end

  describe 'thread safety' do
    it 'handles concurrent session creation' do
      threads = []
      
      10.times do |i|
        threads << Thread.new do
          manager.create_session("192.168.1.#{i}", :command, "cmd#{i}")
        end
      end
      
      threads.each(&:join)
      
      expect(manager.active_sessions.length).to eq(10)
      expect(manager.active_sessions.keys.uniq.length).to eq(10) # All unique IDs
    end

    it 'handles concurrent data addition' do
      sessions = []
      5.times { |i| sessions << manager.create_session("192.168.1.#{i}", :command, "cmd#{i}") }
      
      threads = []
      sessions.each_with_index do |session, i|
        threads << Thread.new do
          manager.add_data_to_session("192.168.1.#{i}", "data#{i}", :command)
        end
      end
      
      threads.each(&:join)
      
      expect(manager.completed_sessions.length).to eq(5)
      expect(manager.active_sessions).to be_empty
    end
  end
end