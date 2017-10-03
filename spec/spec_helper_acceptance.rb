require 'hiera'
require 'beaker/testmode_switcher/dsl'
require 'beaker-rspec' if ENV['BEAKER_TESTMODE'] != 'local'

def install_from_local_checkout_on(hosts, name)
  home = `bundle list #{name}`.strip
  puts "Installing #{name} from #{home}"
  system("cd #{home} && bundle install && bundle list && bundle exec rake build && mv -v pkg/#{name}-*.gem pkg/#{name}.gem")
  scp_to(hosts, "#{home}/pkg/#{name}.gem", "/tmp/#{name}.gem")
  on(hosts, "/opt/puppetlabs/puppet/bin/gem install /tmp/#{name}.gem")
end

if ENV['BEAKER_TESTMODE'] != 'local'
  puts 'travis_fold:start:beaker_install'
  require 'beaker/puppet_install_helper'
  require 'beaker/module_install_helper'
  run_puppet_install_helper
  install_module_on(hosts)
  install_module_dependencies_on(hosts)

  unless ENV['BEAKER_provision'] == 'no'
    puts "Installing dependencies for #{default.platform}"
    install_from_local_checkout_on default, 'childprocesscore'
    install_from_local_checkout_on default, 'childprocess' if default.platform =~ /^win-/
    install_from_local_checkout_on default, 'puppet-resource_api'
  end
  puts 'travis_fold:end:beaker_install'
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
  rescue Exception => e # rubocop:disable Lint/RescueException
    raise unless try < max_retry_count && (error_matcher.nil? || e.message =~ error_matcher)
    sleep retry_wait_interval_secs
    retry
  end
end

RSpec.configure do |c|
  # Project root
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # Readable test descriptions
  c.formatter = :documentation
end

shared_context 'a puppet resource run' do |typename, name, **beaker_opts|
  before(:all) do
    @result = resource(typename, name, beaker_opts)
  end

  it 'does not return an error' do
    expect(@result.stderr).not_to match(%r{\b})
  end
end

def puppet_resource_should_show(property_name, value = nil)
  it "reports the correct '#{property_name}' value" do
    # this overloading allows for passing either a key or a key and value
    # and naively picks the key from @config if it exists. This is because
    # @config is only available in the context of a test, and not in the context
    # of describe or context
    regex = if value.nil?
              %r{(#{property_name})(\s*)(=>)(\s*)}
            else
              %r{(#{property_name})(\s*)(=>)(\s*)('#{value}'|"#{value}"|#{value})}i
            end
    expect(@result.stdout).to match(regex)
  end
end
