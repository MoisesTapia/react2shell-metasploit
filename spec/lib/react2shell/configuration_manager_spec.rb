# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../lib/react2shell/configuration_manager'

RSpec.describe React2Shell::ConfigurationManager do
  let(:mock_module) { create_mock_msf_module }
  let(:config_manager) { described_class.new(mock_module) }

  describe '#validate_options' do
    it 'returns no errors for valid configuration' do
      errors = config_manager.validate_options
      expect(errors).to be_empty
    end

    it 'requires RHOSTS to be set' do
      mock_module.datastore['RHOSTS'] = ''
      errors = config_manager.validate_options
      
      expect(errors).to include('RHOSTS not set')
    end

    it 'requires LHOST to be set' do
      mock_module.datastore['LHOST'] = ''
      errors = config_manager.validate_options
      
      expect(errors).to include('LHOST not set')
    end

    it 'validates port ranges' do
      mock_module.datastore['SRVPORT'] = 70000
      errors = config_manager.validate_options
      
      expect(errors).to include('SRVPORT must be between 1 and 65535')
    end

    it 'requires either FILEPATH or CMD' do
      mock_module.datastore['FILEPATH'] = ''
      mock_module.datastore['CMD'] = ''
      errors = config_manager.validate_options
      
      expect(errors).to include('Either FILEPATH or CMD must be specified')
    end

    it 'prevents both FILEPATH and CMD being set' do
      mock_module.datastore['FILEPATH'] = '/etc/passwd'
      mock_module.datastore['CMD'] = 'ls -la'
      errors = config_manager.validate_options
      
      expect(errors).to include('Cannot specify both FILEPATH and CMD - choose one')
    end

    it 'validates absolute file paths' do
      mock_module.datastore['FILEPATH'] = 'relative/path'
      mock_module.datastore['CMD'] = ''
      errors = config_manager.validate_options
      
      expect(errors).to include('FILEPATH must be an absolute path starting with /')
    end
  end

  describe '#check_connectivity' do
    it 'returns true when target responds' do
      allow(mock_module).to receive(:send_request_cgi).and_return(create_mock_response)
      
      result = config_manager.check_connectivity
      expect(result).to be true
    end

    it 'returns false when target does not respond' do
      allow(mock_module).to receive(:send_request_cgi).and_return(nil)
      
      result = config_manager.check_connectivity
      expect(result).to be false
    end

    it 'handles exceptions gracefully' do
      allow(mock_module).to receive(:send_request_cgi).and_raise(StandardError, 'Network error')
      
      result = config_manager.check_connectivity
      expect(result).to be false
    end
  end

  describe '#get_oob_url' do
    it 'constructs proper OOB URL' do
      url = config_manager.get_oob_url
      
      expect(url).to match(%r{^http://[\d.]+:\d+/$})
      expect(url).to include(mock_module.datastore['LHOST'])
      expect(url).to include(mock_module.datastore['SRVPORT'].to_s)
    end

    it 'uses SRVHOST when available' do
      mock_module.datastore['SRVHOST'] = '10.0.0.1'
      url = config_manager.get_oob_url
      
      expect(url).to include('10.0.0.1')
    end
  end

  describe '#determine_exploit_mode' do
    it 'returns command_execution when CMD is set' do
      mock_module.datastore['CMD'] = 'ls -la'
      mock_module.datastore['FILEPATH'] = ''
      
      mode = config_manager.determine_exploit_mode
      expect(mode).to eq(:command_execution)
    end

    it 'returns file_exfiltration when FILEPATH is set' do
      mock_module.datastore['FILEPATH'] = '/etc/passwd'
      mock_module.datastore['CMD'] = ''
      
      mode = config_manager.determine_exploit_mode
      expect(mode).to eq(:file_exfiltration)
    end

    it 'raises error when neither is set' do
      mock_module.datastore['FILEPATH'] = ''
      mock_module.datastore['CMD'] = ''
      
      expect { config_manager.determine_exploit_mode }.to raise_error(ArgumentError)
    end
  end

  describe '#get_filepath' do
    it 'returns configured filepath' do
      expected_path = '/etc/passwd'
      mock_module.datastore['FILEPATH'] = expected_path
      
      result = config_manager.get_filepath
      expect(result).to eq(expected_path)
    end
  end

  describe '#get_command' do
    it 'returns configured command' do
      expected_cmd = 'ls -la'
      mock_module.datastore['CMD'] = expected_cmd
      
      result = config_manager.get_command
      expect(result).to eq(expected_cmd)
    end
  end

  describe '#get_listener_address' do
    it 'returns formatted listener address' do
      address = config_manager.get_listener_address
      
      expect(address).to match(/[\d.]+:\d+/)
      expect(address).to include(':')
    end
  end

  describe '#use_ssl?' do
    it 'returns SSL configuration' do
      mock_module.datastore['SSL'] = true
      expect(config_manager.use_ssl?).to be true
      
      mock_module.datastore['SSL'] = false
      expect(config_manager.use_ssl?).to be false
    end
  end
end