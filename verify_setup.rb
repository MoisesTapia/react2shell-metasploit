#!/usr/bin/env ruby
# frozen_string_literal: true

# Simple verification script to check if all files are properly structured

puts "🔍 Verifying React2Shell Module Setup..."
puts "=" * 50

# Check main module file
if File.exist?('react2shell_rce.rb')
  puts "✅ Main module file: react2shell_rce.rb"
else
  puts "❌ Missing main module file: react2shell_rce.rb"
  exit 1
end

# Check library files
lib_files = [
  'lib/react2shell/exploit_engine.rb',
  'lib/react2shell/payload_generator.rb', 
  'lib/react2shell/oob_listener.rb',
  'lib/react2shell/configuration_manager.rb'
]

lib_files.each do |file|
  if File.exist?(file)
    puts "✅ Library file: #{file}"
  else
    puts "❌ Missing library file: #{file}"
    exit 1
  end
end

# Check test files
test_files = [
  'spec/spec_helper.rb',
  'spec/support/test_helpers.rb',
  'spec/lib/react2shell/exploit_engine_spec.rb',
  'spec/lib/react2shell/payload_generator_spec.rb',
  'spec/lib/react2shell/oob_listener_spec.rb',
  'spec/lib/react2shell/configuration_manager_spec.rb'
]

test_files.each do |file|
  if File.exist?(file)
    puts "✅ Test file: #{file}"
  else
    puts "❌ Missing test file: #{file}"
    exit 1
  end
end

# Check configuration files
config_files = [
  'Gemfile',
  'Rakefile',
  '.rspec'
]

config_files.each do |file|
  if File.exist?(file)
    puts "✅ Config file: #{file}"
  else
    puts "❌ Missing config file: #{file}"
    exit 1
  end
end

puts "=" * 50
puts "🎉 All files are present and accounted for!"
puts ""
puts "📋 Next steps:"
puts "1. Install Ruby (if not already installed)"
puts "2. Run: gem install bundler"
puts "3. Run: bundle install"
puts "4. Run: bundle exec rspec"
puts "5. Copy to Metasploit: ~/.msf4/modules/exploits/multi/http/"
puts ""
puts "🚀 Setup verification complete!"