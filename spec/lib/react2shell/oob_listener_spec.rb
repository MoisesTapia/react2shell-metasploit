# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../lib/react2shell/oob_listener'

RSpec.describe React2Shell::OOBListener do
  let(:mock_module) { create_mock_msf_module }
  let(:listener) { described_class.new(mock_module) }

  describe '#initialize' do
    it 'initializes with default values' do
      expect(listener.received_data).to be_nil
      expect(listener.server_thread).to be_nil
    end
  end

  describe '#handle_post_request' do
    let(:request) { { body: 'test data' } }
    let(:source_ip) { '192.168.1.100' }

    before do
      # Create a session to receive the data
      listener.create_session(source_ip, :unknown, 'test')
    end

    it 'processes POST request data' do
      response = listener.handle_post_request(request, source_ip)
      
      expect(response).to include('HTTP/1.1 200 OK')
      expect(response).to include('OK')
    end

    it 'stores received data' do
      listener.handle_post_request(request, source_ip)
      
      expect(listener.has_received_data?).to be true
      expect(listener.get_received_data).to eq('test data')
    end

    it 'handles command output format' do
      cmd_request = { body: 'CMD_OUTPUT:command result' }
      listener.handle_post_request(cmd_request, source_ip)
      
      expect(listener.get_received_data).to eq('command result')
    end

    it 'handles empty request body' do
      empty_request = { body: '' }
      response = listener.handle_post_request(empty_request, source_ip)
      
      expect(response).to include('HTTP/1.1 200 OK')
    end

    it 'adds data to session manager' do
      expect(listener.session_manager).to receive(:add_data_to_session)
        .with(source_ip, 'test data', :file)
        .and_return(true)
      
      listener.handle_post_request(request, source_ip)
    end

    it 'handles session manager failure' do
      allow(listener.session_manager).to receive(:add_data_to_session).and_return(false)
      
      response = listener.handle_post_request(request, source_ip)
      
      expect(response).to include('HTTP/1.1 500')
    end
  end

  describe '#store_received_data' do
    it 'stores data with metadata' do
      test_data = 'test content'
      listener.store_received_data(test_data, :file)
      
      metadata = listener.get_received_data_with_metadata
      expect(metadata[:content]).to eq(test_data)
      expect(metadata[:type]).to eq(:file)
      expect(metadata[:size]).to eq(test_data.length)
      expect(metadata[:timestamp]).to be_a(Time)
    end
  end

  describe '#has_received_data?' do
    it 'returns false initially' do
      expect(listener.has_received_data?).to be false
    end

    it 'returns true after receiving data' do
      listener.store_received_data('test', :file)
      expect(listener.has_received_data?).to be true
    end
  end

  describe '#get_received_data' do
    it 'returns nil when no data received' do
      expect(listener.get_received_data).to be_nil
    end

    it 'returns data content when available' do
      test_data = 'test content'
      listener.store_received_data(test_data, :file)
      
      expect(listener.get_received_data).to eq(test_data)
    end
  end

  describe 'data parsing' do
    let(:source_ip) { '192.168.1.100' }

    before do
      listener.create_session(source_ip, :unknown, 'test')
    end

    it 'parses command output correctly' do
      request = { body: 'CMD_OUTPUT:ls -la result' }
      listener.handle_post_request(request, source_ip)
      
      expect(listener.get_received_data).to eq('ls -la result')
    end

    it 'treats regular data as file content' do
      request = { body: 'file content here' }
      listener.handle_post_request(request, source_ip)
      
      metadata = listener.get_received_data_with_metadata
      expect(metadata[:type]).to eq(:file)
      expect(metadata[:content]).to eq('file content here')
    end
  end

  describe 'loot storage' do
    it 'stores data as Metasploit loot' do
      test_data = 'sensitive file content'
      
      expect(mock_module).to receive(:store_loot).with(
        'react2shell.oob.file',
        'text/plain',
        '192.168.1.100',
        test_data,
        anything,
        'React2Shell OOB file data'
      ).and_return('/tmp/loot_file')
      
      listener.store_received_data(test_data, :file)
    end

    it 'handles loot storage errors gracefully' do
      allow(mock_module).to receive(:store_loot).and_raise(StandardError.new('Storage failed'))
      
      expect { listener.store_received_data('test', :file) }.not_to raise_error
    end
  end

  describe 'enhanced data parsing' do
    let(:source_ip) { '192.168.1.100' }

    before do
      listener.create_session(source_ip, :unknown, 'test')
    end

    it 'handles FILE_CONTENT prefix' do
      request = { body: 'FILE_CONTENT:actual file data' }
      listener.handle_post_request(request, source_ip)
      
      expect(listener.get_received_data).to eq('actual file data')
    end

    it 'handles ERROR prefix' do
      request = { body: 'ERROR:command not found' }
      listener.handle_post_request(request, source_ip)
      
      expect(listener.get_received_data).to eq('command not found')
    end

    it 'determines data type from content type header' do
      request = { 
        body: 'binary data', 
        headers: { 'content-type' => 'application/octet-stream' }
      }
      listener.handle_post_request(request, source_ip)
      
      metadata = listener.get_received_data_with_metadata
      expect(metadata[:type]).to eq(:file)
    end
  end

  describe 'OOB URL generation' do
    before do
      listener.instance_variable_set(:@server_host, '192.168.1.1')
      listener.instance_variable_set(:@server_port, 8080)
    end

    it 'generates correct OOB URL' do
      expect(listener.get_oob_url).to eq('http://192.168.1.1:8080/')
    end

    it 'handles 0.0.0.0 binding correctly' do
      listener.instance_variable_set(:@server_host, '0.0.0.0')
      expect(listener.get_oob_url).to eq('http://192.168.1.1:8080/')
    end

    it 'returns nil when server not configured' do
      listener.instance_variable_set(:@server_host, nil)
      expect(listener.get_oob_url).to be_nil
    end
  end

  describe 'server status' do
    it 'reports not running initially' do
      expect(listener.running?).to be false
    end
  end

  describe 'session management integration' do
    let(:target_host) { '192.168.1.100' }

    describe '#create_session' do
      it 'creates session through session manager' do
        session = listener.create_session(target_host, :command, 'test cmd')
        
        expect(session).to be_a(React2Shell::OOBSession)
        expect(session.target_host).to eq(target_host)
        expect(session.expected_data_type).to eq(:command)
        expect(session.source_info).to eq('test cmd')
      end
    end

    describe '#get_session' do
      it 'retrieves session by ID' do
        session = listener.create_session(target_host, :file, 'test.txt')
        
        retrieved = listener.get_session(session.session_id)
        expect(retrieved).to eq(session)
      end
    end

    describe '#get_active_sessions' do
      it 'returns active sessions' do
        session1 = listener.create_session(target_host, :command, 'cmd1')
        session2 = listener.create_session(target_host, :file, 'file1')
        
        active = listener.get_active_sessions
        expect(active).to include(session1, session2)
      end
    end

    describe '#get_completed_sessions' do
      it 'returns completed sessions' do
        session = listener.create_session(target_host, :command, 'cmd')
        
        # Complete the session by adding data
        request = { body: 'CMD_OUTPUT:result' }
        listener.handle_post_request(request, target_host)
        
        completed = listener.get_completed_sessions
        expect(completed).to include(session)
      end
    end

    describe '#get_session_statistics' do
      it 'returns session statistics' do
        listener.create_session(target_host, :command, 'cmd1')
        listener.create_session(target_host, :file, 'file1')
        
        stats = listener.get_session_statistics
        expect(stats[:active_sessions]).to eq(2)
        expect(stats[:total_sessions]).to eq(2)
      end
    end

    describe '#wait_for_session_completion' do
      it 'waits for session completion' do
        session = listener.create_session(target_host, :command, 'cmd')
        
        # Complete session in background thread
        Thread.new do
          sleep(0.1)
          request = { body: 'CMD_OUTPUT:result' }
          listener.handle_post_request(request, target_host)
        end
        
        completed = listener.wait_for_session_completion(5)
        expect(completed).to eq(session)
      end
    end

    describe '#cleanup_timed_out_sessions' do
      it 'cleans up timed out sessions' do
        session = listener.create_session(target_host, :command, 'cmd')
        
        # Simulate timeout
        session.instance_variable_set(:@start_time, Time.now - 400)
        session.instance_variable_set(:@last_activity, Time.now - 400)
        
        cleaned = listener.cleanup_timed_out_sessions(300)
        expect(cleaned).to eq(1)
      end
    end
  end

  describe '#stop_server' do
    it 'cleans up sessions when stopping' do
      listener.create_session('192.168.1.100', :command, 'cmd')
      
      expect(listener.session_manager).to receive(:cleanup_all_sessions)
      
      listener.stop_server
    end
  end

  # Note: Server start/stop tests would require more complex setup
  # and are better suited for integration tests
  describe 'server lifecycle' do
    it 'initializes server configuration' do
      # Test that server can be configured without starting
      expect(listener.server_host).to be_nil
      expect(listener.server_port).to be_nil
    end

    it 'initializes session manager' do
      expect(listener.session_manager).to be_a(React2Shell::SessionManager)
    end
  end
end