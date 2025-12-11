# frozen_string_literal: true

source 'https://rubygems.org'

# Core Ruby libraries (required for Ruby 3.4+)
gem 'base64', '~> 0.2'

# Testing framework
gem 'rspec', '~> 3.13'

# Property-based testing
gem 'rantly', '~> 2.0'

# Development and code quality dependencies
group :development do
  gem 'rubocop', '~> 1.60'
  gem 'rubocop-performance', '~> 1.20'
  gem 'reek', '~> 6.1'
  gem 'flay', '~> 2.13'
  gem 'flog', '~> 4.8'
  gem 'yard', '~> 0.9'
end

# Security analysis tools
group :security do
  gem 'brakeman', '~> 6.0'
  gem 'bundler-audit', '~> 0.9'
end

# Testing utilities
group :test do
  gem 'simplecov', '~> 0.22'
end

# Performance analysis
group :performance do
  gem 'benchmark-ips', '~> 2.13'
  gem 'memory_profiler', '~> 1.0'
end

# Note: In actual Metasploit usage, all dependencies are provided by the framework
# This Gemfile is only for standalone development and testing