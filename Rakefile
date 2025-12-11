# frozen_string_literal: true

require 'rspec/core/rake_task'

# Default task
task default: :spec

# RSpec task
RSpec::Core::RakeTask.new(:spec) do |t|
  t.rspec_opts = '--format documentation --color'
end

# Property-based testing specific task
RSpec::Core::RakeTask.new(:pbt) do |t|
  t.pattern = 'spec/**/*_property_spec.rb'
  t.rspec_opts = '--format documentation --color'
end

# Unit testing specific task  
RSpec::Core::RakeTask.new(:unit) do |t|
  t.pattern = 'spec/**/*_spec.rb'
  t.exclude_pattern = 'spec/**/*_property_spec.rb'
  t.rspec_opts = '--format documentation --color'
end

desc 'Run all tests'
task :test => :spec

desc 'Run tests with coverage'
task :coverage do
  ENV['COVERAGE'] = 'true'
  Rake::Task[:spec].invoke
end