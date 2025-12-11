# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../lib/react2shell/oob_session'

RSpec.describe React2Shell::OOBSession do
  let(:target_host) { '192.168.1.100' }
  let(:session) { described_class.new(target_host, :command, 'test command') }

  describe '#initialize' do
    it 'creates session with unique ID' do
      session1 = described_class.new(target_host)
      session2 = described_class.new(target_host)
      
      expect(session1.session_id).not_to eq(session2.session_id)
      expect(session1.session_id).to match(/^[a-f0-9]{16}$/)
    end

    it 'sets initial values correctly' do
      expect(session.target_host).to eq(target_host)
      expect(session.status).to eq(:waiting)
      expect(session.received_data).to be_empty
      expect(session.start_time).to be_a(Time)
      expect(session.expected_data_type).to eq(:command)
      expect(session.source_info).to eq('test command')
    end
  end

  describe '#add_received_data' do
    let(:test_data) { 'command output' }
    let(:source_ip) { '192.168.1.100' }

    it 'adds data successfully from valid source' do
      result = session.add_received_data(test_data, source_ip, :command)
      
      expect(result).to be true
      expect(session.received_data.length).to eq(1)
      expect(session.get_all_data).to eq(test_data)
    end

    it 'creates data entry with metadata' do
      session.add_received_data(test_data, source_ip, :command)
      
      entry = session.received_data.first
      expect(entry[:content]).to eq(test_data)
      expect(entry[:source_ip]).to eq(source_ip)
      expect(entry[:data_type]).to eq(:command)
      expect(entry[:timestamp]).to be_a(Time)
      expect(entry[:size]).to eq(test_data.length)
      expect(entry[:sequence]).to eq(1)
    end

    it 'updates session status to receiving' do
      expect(session.status).to eq(:waiting)
      
      # Add raw data first (won't complete the session)
      session.add_received_data(test_data, source_ip, :raw)
      
      expect(session.status).to eq(:receiving)
    end

    it 'marks session complete for expected data type' do
      session.add_received_data(test_data, source_ip, :command)
      
      expect(session.is_complete?).to be true
      expect(session.status).to eq(:complete)
    end

    it 'handles multiple data entries' do
      session.add_received_data('first', source_ip, :raw)
      session.add_received_data('second', source_ip, :command)
      
      expect(session.received_data.length).to eq(2)
      expect(session.get_all_data).to eq('firstsecond')
    end

    it 'validates source IP' do
      # Should accept data from target host
      expect(session.add_received_data(test_data, target_host, :command)).to be true
      
      # Should reject data from different host
      expect(session.add_received_data(test_data, '10.0.0.1', :command)).to be false
    end

    it 'allows localhost connections' do
      expect(session.add_received_data(test_data, '127.0.0.1', :command)).to be true
      expect(session.add_received_data(test_data, '::1', :command)).to be true
    end
  end

  describe '#is_complete?' do
    it 'returns false initially' do
      expect(session.is_complete?).to be false
    end

    it 'returns true when status is complete' do
      session.add_received_data('output', target_host, :command)
      expect(session.is_complete?).to be true
    end
  end

  describe '#is_timeout?' do
    it 'returns false for new session' do
      expect(session.is_timeout?(300)).to be false
    end

    it 'returns true for old session' do
      # Simulate old session by setting start time in the past
      session.instance_variable_set(:@start_time, Time.now - 400)
      session.instance_variable_set(:@last_activity, Time.now - 400)
      
      expect(session.is_timeout?(300)).to be true
      expect(session.status).to eq(:timeout)
    end

    it 'does not timeout completed sessions' do
      session.add_received_data('output', target_host, :command)
      session.instance_variable_set(:@start_time, Time.now - 400)
      
      expect(session.is_timeout?(300)).to be false
    end
  end

  describe '#mark_error' do
    it 'sets error status and message' do
      error_msg = 'Network error'
      session.mark_error(error_msg)
      
      expect(session.status).to eq(:error)
      expect(session.get_session_summary[:error_message]).to eq(error_msg)
    end
  end

  describe '#get_session_summary' do
    it 'returns comprehensive session information' do
      session.add_received_data('test data', target_host, :command)
      
      summary = session.get_session_summary
      
      expect(summary[:session_id]).to eq(session.session_id)
      expect(summary[:target_host]).to eq(target_host)
      expect(summary[:status]).to eq(:complete)
      expect(summary[:data_entries]).to eq(1)
      expect(summary[:total_bytes]).to eq(9)
      expect(summary[:expected_type]).to eq(:command)
      expect(summary[:source_info]).to eq('test command')
    end
  end

  describe '#is_active?' do
    it 'returns true for waiting sessions' do
      expect(session.is_active?).to be true
    end

    it 'returns true for receiving sessions' do
      session.add_received_data('partial', target_host, :raw)
      expect(session.is_active?).to be true
    end

    it 'returns false for completed sessions' do
      session.add_received_data('output', target_host, :command)
      expect(session.is_active?).to be false
    end

    it 'returns false for error sessions' do
      session.mark_error('test error')
      expect(session.is_active?).to be false
    end
  end

  describe '#status_description' do
    it 'provides human-readable status' do
      expect(session.status_description).to eq('Waiting for data')
      
      session.add_received_data('test', target_host, :raw)
      expect(session.status_description).to include('Receiving data')
      
      session.add_received_data('output', target_host, :command)
      expect(session.status_description).to include('Complete')
    end
  end

  describe 'completion detection' do
    context 'for command sessions' do
      let(:cmd_session) { described_class.new(target_host, :command, 'ls -la') }

      it 'completes on command output' do
        cmd_session.add_received_data('file list', target_host, :command)
        expect(cmd_session.is_complete?).to be true
      end

      it 'completes on error output' do
        cmd_session.add_received_data('command not found', target_host, :error)
        expect(cmd_session.is_complete?).to be true
      end
    end

    context 'for file sessions' do
      let(:file_session) { described_class.new(target_host, :file, '/etc/passwd') }

      it 'completes on file content' do
        file_session.add_received_data('root:x:0:0', target_host, :file)
        expect(file_session.is_complete?).to be true
      end

      it 'does not complete on command output' do
        file_session.add_received_data('command output', target_host, :command)
        expect(file_session.is_complete?).to be false
      end
    end

    context 'for unknown type sessions' do
      let(:unknown_session) { described_class.new(target_host, :unknown) }

      it 'completes on any non-empty data' do
        unknown_session.add_received_data('any data', target_host, :raw)
        expect(unknown_session.is_complete?).to be true
      end
    end

    it 'completes on explicit completion markers' do
      session.add_received_data('data REACT2SHELL_COMPLETE', target_host, :raw)
      expect(session.is_complete?).to be true
    end
  end

  describe '#cleanup' do
    it 'clears received data and sets status' do
      session.add_received_data('test', target_host, :command)
      session.cleanup
      
      expect(session.received_data).to be_empty
      expect(session.status).to eq(:complete)
    end

    it 'preserves error status during cleanup' do
      session.mark_error('test error')
      session.cleanup
      
      expect(session.status).to eq(:error)
    end
  end
end