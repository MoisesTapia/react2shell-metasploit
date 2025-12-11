# frozen_string_literal: true

# Test helper methods and utilities for React2Shell testing

module TestHelpers
  ##
  # Creates a mock Metasploit module for testing
  def create_mock_msf_module(options = {})
    mock_module = double('MetasploitModule')
    
    # Default datastore values
    default_datastore = {
      'RHOSTS' => '192.168.1.100',
      'LHOST' => '192.168.1.1',
      'SRVHOST' => '192.168.1.1',
      'SRVPORT' => 8080,
      'FILEPATH' => '/etc/passwd',
      'CMD' => '',
      'HTTP_DELAY' => 10,
      'SSL' => false,
      'TARGETURI' => '/'
    }.merge(options[:datastore] || {})
    
    # Mock datastore access
    allow(mock_module).to receive(:datastore).and_return(default_datastore)
    
    # Mock common methods
    allow(mock_module).to receive(:print_status)
    allow(mock_module).to receive(:print_good)
    allow(mock_module).to receive(:print_warning)
    allow(mock_module).to receive(:print_error)
    allow(mock_module).to receive(:vprint_status)
    allow(mock_module).to receive(:vprint_error)
    allow(mock_module).to receive(:vprint_good)
    allow(mock_module).to receive(:print_line)
    
    # Mock network methods
    allow(mock_module).to receive(:send_request_cgi).and_return(nil)
    allow(mock_module).to receive(:normalize_uri) { |path| path }
    allow(mock_module).to receive(:target_uri).and_return(double(path: '/'))
    allow(mock_module).to receive(:rhost).and_return(default_datastore['RHOSTS'])
    allow(mock_module).to receive(:store_loot).and_return('/tmp/loot_file')
    
    mock_module
  end
  
  ##
  # Creates a mock HTTP response
  def create_mock_response(code: 200, body: '', headers: {})
    response = double('HttpResponse')
    allow(response).to receive(:code).and_return(code)
    allow(response).to receive(:body).and_return(body)
    allow(response).to receive(:headers).and_return(headers)
    response
  end
  
  ##
  # Generates random valid file paths for testing
  def random_filepath
    dirs = %w[/etc /var /tmp /home /usr]
    files = %w[passwd shadow hosts config.txt data.json log.txt]
    "#{dirs.sample}/#{files.sample}"
  end
  
  ##
  # Generates random shell commands for testing
  def random_command
    commands = [
      'ls -la',
      'cat /etc/passwd',
      'whoami',
      'id',
      'uname -a',
      'ps aux'
    ]
    commands.sample
  end
  
  ##
  # Generates random JavaScript payloads for testing
  def random_javascript_payload
    payloads = [
      "console.log('test')",
      "process.exit(0)",
      "require('fs').readFileSync('/etc/passwd')",
      "Math.random()",
      "new Date().toString()"
    ]
    payloads.sample
  end
  
  ##
  # Validates JSON structure
  def valid_json?(string)
    JSON.parse(string)
    true
  rescue JSON::ParserError
    false
  end
  
  ##
  # Validates Flight Protocol chunk structure
  def valid_flight_chunk?(json_string)
    return false unless valid_json?(json_string)
    
    chunk = JSON.parse(json_string)
    required_keys = %w[then status reason value _response]
    
    required_keys.all? { |key| chunk.key?(key) }
  end
end

# Include helpers in RSpec
RSpec.configure do |config|
  config.include TestHelpers
end