# frozen_string_literal: true

require 'rspec'
require 'rantly/rspec_extensions'

# Configure RSpec
RSpec.configure do |config|
  # Use documentation format for better test output
  config.default_formatter = 'doc'
  
  # Configure property-based testing
  config.before(:suite) do
    # Set default number of iterations for property tests
    Rantly.default_size = 100
  end
  
  # Test environment setup
  config.before(:each) do
    # Reset any global state before each test
  end
  
  config.after(:each) do
    # Cleanup after each test
  end
  
  # Shared test utilities
  config.shared_context_metadata_behavior = :apply_to_host_groups
  
  # Configure expectations
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end
  
  # Configure mocks
  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end
  
  # Filter out external gems from backtraces
  config.filter_gems_from_backtrace "rspec-quickcheck"
end

# Load test support files
Dir[File.join(__dir__, 'support', '**', '*.rb')].each { |f| require f }