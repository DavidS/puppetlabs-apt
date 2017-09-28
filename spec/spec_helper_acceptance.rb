require 'hiera'
require 'beaker/testmode_switcher/dsl'
require 'beaker-rspec' if ENV['BEAKER_TESTMODE'] != 'local'

if ENV['BEAKER_TESTMODE'] != 'local'
  require 'beaker/puppet_install_helper'
  require 'beaker/module_install_helper'
  run_puppet_install_helper
  install_module_on(hosts)
  install_module_dependencies_on(hosts)
end

# This method allows a block to be passed in and if an exception is raised
# that matches the 'error_matcher' matcher, the block will wait a set number
# of seconds before retrying.
# Params:
# - max_retry_count - Max number of retries
# - retry_wait_interval_secs - Number of seconds to wait before retry
# - error_matcher - Matcher which the exception raised must match to allow retry
# Example Usage:
# retry_on_error_matching(3, 5, /OpenGPG Error/) do
#   apply_manifest(pp, :catch_failures => true)
# end
def retry_on_error_matching(max_retry_count = 3, retry_wait_interval_secs = 5, error_matcher = nil)
  try = 0
  begin
    try += 1
    yield
  rescue Exception => e
    if try < max_retry_count && (error_matcher.nil? || e.message =~ error_matcher)
      sleep retry_wait_interval_secs
      retry
    else
      raise
    end
  end
end

RSpec.configure do |c|
  # Project root
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # Readable test descriptions
  c.formatter = :documentation
end

if ENV['BEAKER_provision'] == 'yes'
  scp_to(hosts, '/home/david/git/puppet-resource_api/pkg/puppet-resource_api-0.1.0.gem', '/tmp/puppet-resource_api-0.1.0.gem')
  on(hosts, '/opt/puppetlabs/puppet/bin/gem install /tmp/puppet-resource_api-0.1.0.gem')
end

shared_context 'a puppet resource run' do |typename, name, **beaker_opts|
  before(:all) do
    @result = resource(typename, name, beaker_opts)
  end

  it 'should not return an error' do
    expect(@result.stderr).not_to match(/\b/)
  end
end

def puppet_resource_should_show(property_name, value=nil)
  it "should report the correct '#{property_name}' value" do
    # this overloading allows for passing either a key or a key and value
    # and naively picks the key from @config if it exists. This is because
    # @config is only available in the context of a test, and not in the context
    # of describe or context
    regex = if value.nil?
              /(#{property_name})(\s*)(=>)(\s*)/
            else
              /(#{property_name})(\s*)(=>)(\s*)('#{value}'|"#{value}"|#{value})/i
            end
    expect(@result.stdout).to match(regex)
  end
end
