require 'puppet/resource_api'

Puppet::ResourceApi.register_type(
  name: 'apt_key2',
  docs: <<-EOS,
      This type provides Puppet with the capabilities to manage GPG keys needed
      by apt to perform package validation. Apt has it's own GPG keyring that can
      be manipulated through the `apt-key` command.

      apt_key { '6F6B15509CF8E59E6E469F327F438280EF8D349F':
        source => 'http://apt.puppetlabs.com/pubkey.gpg'
      }

      **Autorequires**:
      If Puppet is given the location of a key file which looks like an absolute
      path this type will autorequire that file.
    EOS
  attributes:   {
    ensure:      {
      type:    'Enum[present, absent]',
      desc:    'Whether this apt key should be present or absent on the target system.',
      default: 'present',
    },
    id:          {
      type:      'Variant[Pattern[/\A(0x)?[0-9a-fA-F]{8}\Z/], Pattern[/\A(0x)?[0-9a-fA-F]{16}\Z/], Pattern[/\A(0x)?[0-9a-fA-F]{40}\Z/]]',
      desc:      'The fingerprint of the key you want to manage.',
      behaviour: :namevar,
    },
    content:     {
      type: 'Optional[String]',
      desc: 'The content of, or string representing, a GPG key.',
      behaviour: :parameter,
    },
    source:      {
      type: 'Variant[Stdlib::Absolutepath, Pattern[/\A(https?|ftp):\/\//]]',
      desc: 'Location of a GPG key file, /path/to/file, ftp://, http:// or https://',
      behaviour: :parameter,
    },
    server:      {
      type:      'Pattern[/\A((hkp|http|https):\/\/)?([a-z\d])([a-z\d-]{0,61}\.)+[a-z\d]+(:\d{2,5})?$/]',
      desc:      'The key server to fetch the key from based on the ID. It can either be a domain name or url.',
      behaviour: :parameter,
      default:   :'keyserver.ubuntu.com',
    },
    options:     {
      type: 'Optional[String]',
      desc: 'Additional options to pass to apt-key\'s --keyserver-options.',
    },
    fingerprint: {
      type:      'Pattern[/[a-f]{40}/]',
      desc:      'The 40-digit hexadecimal fingerprint of the specified GPG key.',
      behaviour: :read_only,
    },
    long:        {
      type:      'Pattern[/[a-f]{16}/]',
      desc:      'The 16-digit hexadecimal id of the specified GPG key.',
      behaviour: :read_only,
    },
    short:       {
      type:      'Pattern[/[a-f]{8}/]',
      desc:      'The 8-digit hexadecimal id of the specified GPG key.',
      behaviour: :read_only,
    },
    expired:     {
      type:      'Boolean',
      desc:      'Indicates if the key has expired.',
      behaviour: :read_only,
    },
    expiry:      {
      # TODO: should be DateTime
      type:      'String',
      desc:      'The date the key will expire, or nil if it has no expiry date, in ISO format.',
      behaviour: :read_only,
    },
    size:        {
      type:      'Integer',
      desc:      'The key size, usually a multiple of 1024.',
      behaviour: :read_only,
    },
    type:        {
      type:      'String',
      desc:      'The key type, one of: rsa, dsa, ecc, ecdsa.',
      behaviour: :read_only,
    },
    created:     {
      type:      'String',
      desc:      'Date the key was created, in ISO format.',
      behaviour: :read_only,
    },
  },
  autorequires: {
    file:    '$source', # will evaluate to the value of the `source` attribute
    package: 'apt',
  },
  features: ['canonicalize'],
)
