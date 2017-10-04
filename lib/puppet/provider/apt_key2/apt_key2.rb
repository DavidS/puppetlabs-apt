require 'net/ftp'
require 'open-uri'
require 'puppet/resource_api'
require 'tempfile'

# Implementation for the apt_key type using the Resource API.
class Puppet::Provider::AptKey2::AptKey2
  def initialize
    @apt_key_cmd = Puppet::ResourceApi::Command.new 'apt-key'
    @gpg_cmd = Puppet::ResourceApi::Command.new '/usr/bin/gpg'
  end

  def canonicalize(context, resources)
    resources.each do |r|
      r[:name] ||= r[:id]
      r[:name] = if r[:name].start_with?('0x')
                   r[:name][2..-1].upcase
                 else
                   r[:name].upcase
                 end

      # If an 8 or 16 character short was provided; change the name to the full 40 character fingerprint
      # For any other length; leave the name unchanged. This value will subsequently fail validation.
      # TODO: The full 40 characters could be substituted in any time r[:name].length != 40 but to remain like-for-like
      # with the pre resource-api version of this type, allow the name to fail validation if not 8, 16 or 40 chars long.
      if [8, 16].include?(r[:name].length)
        context.warning(r[:name], 'The name should be a full fingerprint (40 characters) to avoid collision attacks, see the README for details.')
        fingerprint = key_list_lines(context)
                      .select { |l| l.start_with?('fpr:') }
                      .map { |l| l.split(':').last }
                      .find { |fp| fp.end_with? r[:name] }
        r[:name] = fingerprint if fingerprint
      end

      r[:id] = r[:name]
    end
  end

  def key_list_lines(context)
    result = @apt_key_cmd.run(context, 'adv', '--list-keys', '--with-colons', '--fingerprint', '--fixed-list-mode',
                              stdout_destination: :store, stderr_loglevel: :debug)
    result.stdout.each_line.map(&:strip)
  end

  def get(context)
    pub_line   = nil
    fpr_line   = nil

    key_list_lines(context).map { |line|
      if line.start_with?('pub')
        pub_line = line
        # reset fpr_line, to skip any previous subkeys which were collected
        fpr_line = nil
      elsif line.start_with?('fpr')
        fpr_line = line
      end

      next unless pub_line && fpr_line

      hash = self.class.key_line_to_hash(pub_line, fpr_line)

      # reset scanning
      pub_line = nil
      fpr_line = nil

      hash
    }.compact!
  end

  def self.key_line_to_hash(pub_line, fpr_line)
    pub_split = pub_line.split(':')
    fpr_split = fpr_line.split(':')

    # set key type based on types defined in /usr/share/doc/gnupg/DETAILS.gz
    key_type  = case pub_split[3]
                when '1'
                  :rsa
                when '17'
                  :dsa
                when '18'
                  :ecc
                when '19'
                  :ecdsa
                else
                  :unrecognized
                end

    fingerprint = fpr_split.last
    expiry      = pub_split[6].empty? ? nil : Time.at(pub_split[6].to_i).utc

    {
      ensure:      'present',
      name:        fingerprint,
      id:          fingerprint,
      fingerprint: fingerprint,
      long:        fingerprint[-16..-1], # last 16 characters of fingerprint
      short:       fingerprint[-8..-1], # last 8 characters of fingerprint
      size:        pub_split[2].to_i,
      type:        key_type,
      created:     Time.at(pub_split[5].to_i).utc.to_s,
      expiry:      expiry.to_s,
      expired:     (expiry && Time.now >= expiry) ? true : false,
    }
  end

  def set(context, changes)
    changes.each do |name, change|
      is = change.key?(:is) ? change[:is] : get_single(name)
      should = change[:should]

      is = { name: name, ensure: 'absent' } if is.nil?
      should = { name: name, ensure: 'absent' } if should.nil?

      if is[:ensure].to_s == 'absent' && should[:ensure].to_s == 'present'
        create(context, name, should)
      elsif is[:ensure].to_s == 'present' && should[:ensure].to_s == 'absent'
        delete(context, name)
      end
    end
    # target_state.each do |title, resource|
    #   if resource[:source] && resource[:content]
    #     logger.fail(title, 'The properties content and source are mutually exclusive')
    #     next
    #   end
  end

  def create(context, name, should)
    context.creating(name) do
      if should[:source].nil? && should[:content].nil?
        # Breaking up the command like this is needed because it blows up
        # if --recv-keys isn't the last argument.
        args = ['adv', '--keyserver', should[:server].to_s]
        if should[:options]
          args.push('--keyserver-options', should[:options])
        end
        args.push('--recv-keys', should[:name])
        # apt-key may write warnings to stdout instead of stderr, therefore make stdout visible
        @apt_key_cmd.run(context, *args, stdout_loglevel: :notice)
      elsif should[:content]
        add_key_from_content(context, name, should[:content])
      elsif should[:source]
        add_key_from_content(context, name, content_from_source(should[:source]))
        # In case we really screwed up, better safe than sorry.
      else
        context.fail("an unexpected condition occurred while trying to add the key: #{name} (content: #{should[:content].inspect}, source: #{should[:source].inspect})")
      end
    end
  end

  def delete(context, name)
    context.deleting(name) do
      # Although canonicalize logs a warning NOT to use the short id instead of all 40 characters, `apt-key del` fails to delete
      # on some systems unless the short id is used. Additionally, such systems will return 0 even though deletion failed.
      # Ref: https://bugs.launchpad.net/ubuntu/+source/apt/+bug/1481871
      @apt_key_cmd.run(context, 'del', name[-8..-1])

      # begin
      #   apt_key('del', resource[:short])
      #   r = execute(["#{command(:apt_key)} list | grep '/#{resource[:short]}\s'"], failonfail: false)
      # end while r.exitstatus.zero?
    end
  end

  def add_key_from_content(context, name, content)
    temp_key_file(context, name, content) do |key_file|
      @apt_key_cmd.run(context, 'add', key_file)
    end
  end

  # This method writes out the specified contents to a temporary file and
  # confirms that the fingerprint from the file, matches the long key that is in the manifest
  def temp_key_file(context, name, content)
    file = Tempfile.new('apt_key')
    begin
      file.write content
      file.close
      if File.executable? '/usr/bin/gpg'
        extracted_keys =
          @gpg_cmd.run(context,
                       '--with-fingerprint', '--with-colons', file.path,
                       stdout_destination: :store)
                  .stdout
                  .each_line
                  .select { |line| line =~ %r{^fpr:} }
                  .map { |fpr| fpr.strip.split(':')[9] }

        if extracted_keys.include? name
          context.debug('Fingerprint verified against extracted key')
        elsif extracted_keys.any? { |k| k =~ %r{#{name}$} }
          context.debug('Fingerprint matches the extracted key')
        else
          raise ArgumentError, "The fingerprint in your manifest (#{name}) and the fingerprint from content/source (#{extracted_keys.inspect}) do not match. "\
            ' Please check there is not an error in the name or check the content/source is legitimate.'
        end
      else
        context.warning('/usr/bin/gpg cannot be found for verification of the fingerprint.')
      end
      yield file.path
    ensure
      file.close
      file.unlink
    end
  end

  def content_from_source(uri)
    parsed_uri = URI.parse(uri)
    if parsed_uri.scheme.nil?
      raise "The file #{uri} does not exist" unless File.exist?(uri)
      # Because the tempfile method has to return a live object to prevent GC
      # of the underlying file from occuring too early, we also have to return
      # a file object here.  The caller can still call the #path method on the
      # closed file handle to get the path.
      File.read(uri)
    else
      begin
        # Only send basic auth if URL contains userinfo
        # Some webservers (e.g. Amazon S3) return code 400 if empty basic auth is sent
        if parsed_uri.userinfo.nil?
          parsed_uri.read
        else
          user_pass = parsed_uri.userinfo.split(':')
          parsed_uri.userinfo = ''
          open(parsed_uri, http_basic_authentication: user_pass).read
        end
      rescue OpenURI::HTTPError, Net::FTPPermError => e
        raise "#{e.message} for #{uri}"
      rescue SocketError
        raise "could not resolve #{uri}"
      end
    end
  end
end
