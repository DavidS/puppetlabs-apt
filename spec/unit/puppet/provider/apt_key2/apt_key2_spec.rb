require 'spec_helper'

# TODO: needs some cleanup/helper to avoid this misery
module Puppet::Provider::AptKey2; end
require 'puppet/provider/apt_key2/apt_key2'

RSpec.describe Puppet::Provider::AptKey2::AptKey2 do
  subject(:provider) { described_class.new }

  let(:context) { instance_double('Puppet::ResourceApi::BaseContext', 'context') }
  let(:apt_key_cmd) { instance_double('Puppet::ResourceApi::Command', 'apt_key_cmd') }
  let(:gpg_cmd) { instance_double('Puppet::ResourceApi::Command', 'gpg_cmd') }

  let(:key_list) do
    <<EOS
Executing: /tmp/apt-key-gpghome.4VkaIao1Ca/gpg.1.sh --list-keys --with-colons --fingerprint --fixed-list-mode
tru:t:1:1505150630:0:3:1:5
pub:-:4096:1:EDA0D2388AE22BA9:1495478513:1747766513::-:::scSC::::::23::0:
rvk:::1::::::80E976F14A508A48E9CA3FE9BC372252CA1CF964:80:
rvk:::1::::::FBFABDB541B5DC955BD9BA6EDB16CF5BB12525C4:80:
rvk:::1::::::309911BEA966D0613053045711B4E5FF15B0FD82:80:
fpr:::::::::6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9:
uid:-::::1495478513::4B4AF158B381AC576A482DF47825CC13569C98D5::Debian Security Archive Automatic Signing Key (9/stretch) <ftpmaster@debian.org>::::::::::0:
sub:-:4096:1:AA8E81B4331F7F50:1495478513:1747766513:::::s::::::23:
fpr:::::::::379483D8B60160B155B372DDAA8E81B4331F7F50:
pub:-:4096:1:7638D0442B90D010:1416603673:1668891673::-:::scSC:::::::
rvk:::1::::::309911BEA966D0613053045711B4E5FF15B0FD82:80:
rvk:::1::::::FBFABDB541B5DC955BD9BA6EDB16CF5BB12525C4:80:
rvk:::1::::::80E976F14A508A48E9CA3FE9BC372252CA1CF964:80:
fpr:::::::::126C0D24BD8A2942CC7DF8AC7638D0442B90D010:
uid:-::::1416603673::15C761B84F0C9C293316B30F007E34BE74546B48::Debian Archive Automatic Signing Key (8/jessie) <ftpmaster@debian.org>:
EOS
  end

  before(:each) do
    allow(context).to receive(:is_a?).with(Puppet::ResourceApi::BaseContext).and_return(true)
    allow(Puppet::ResourceApi::Command).to receive(:new).with('apt-key').and_return(apt_key_cmd)
    allow(Puppet::ResourceApi::Command).to receive(:new).with('/usr/bin/gpg').and_return(gpg_cmd)
    # the provider should never call into the system on its own
    expect(provider).not_to receive(:`) # rubocop:disable RSpec/ExpectInHook
  end

  describe '#canonicalize(resources)' do
    before(:each) do
      allow(apt_key_cmd).to receive(:run)
        .with(context,
              'adv', '--list-keys', '--with-colons', '--fingerprint', '--fixed-list-mode',
              stdout_destination: :store, stderr_loglevel: :debug)
        .and_return(OpenStruct.new(stdout: key_list))
      allow(context).to receive(:warning)
      allow(context).to receive(:debug)
    end

    it('works with empty inputs') { expect(provider.canonicalize(context, [])).to eq [] }
    it('cleans up 0x hex numbers') { expect(provider.canonicalize(context, [{ name: '0xabcd' }])).to eq [{ name: 'ABCD', id: 'ABCD' }] }
    it('upcases bare hex numbers alone') { expect(provider.canonicalize(context, [{ name: 'abcd' }])).to eq [{ name: 'ABCD', id: 'ABCD' }] }
    it('leaves bare upper case hex numbers alone') { expect(provider.canonicalize(context, [{ name: 'ABCD' }])).to eq [{ name: 'ABCD', id: 'ABCD' }] }
    it('handles multiple inputs') do
      expect(provider.canonicalize(context,
                                   [{ name: '0xabcd' },
                                    { name: 'abcd' },
                                    { name: 'ABCD' }]))
        .to eq [{ name: 'ABCD', id: 'ABCD' },
                { name: 'ABCD', id: 'ABCD' },
                { name: 'ABCD', id: 'ABCD' }]
    end
    it('extends short fingerprints to full 40 chars if the key exists') {
      expect(provider.canonicalize(context, [{ name: '2B90D010' }])).to eq [{ name: '126C0D24BD8A2942CC7DF8AC7638D0442B90D010', id: '126C0D24BD8A2942CC7DF8AC7638D0442B90D010' }]
    }
    it('handles invalid inputs') do
      expect { provider.canonicalize(context, [{ name: 'not a hex number' }]) }.not_to raise_error
    end
  end

  describe '.key_line_to_hash(pub, fpr)' do
    subject(:result) { described_class.key_line_to_hash(pub, fpr) }

    let(:pub) { "pub:-:4096:#{key_type}:7638D0442B90D010:1416603673:1668891673::-:::scSC:::::::" }
    let(:fpr) { "fpr:::::::::#{fingerprint}:" }

    let(:key_type) { :foo }

    let(:short) { 'a' * 8 }
    let(:long) { ('1' * 8) + short }
    let(:fingerprint) { 'f' * (40 - 16) + long }

    it('returns the fingerprint') { expect(result[:fingerprint]).to eq fingerprint }
    it('returns the id') { expect(result[:id]).to eq fingerprint }
    it('returns the name') { expect(result[:name]).to eq fingerprint }
    it('returns the long fingerprint') { expect(result[:long]).to eq long }
    it('returns the short fingerprint') { expect(result[:short]).to eq short }

    [[1, :rsa], [17, :dsa], [18, :ecc], [19, :ecdsa], [:foo, :unrecognized]].each do |key_type, value|
      context "with a key type of #{key_type}" do
        let(:key_type) { key_type }

        it("returns #{value.inspect} as key type") { expect(result[:type]).to eq value }
      end
    end
  end

  describe '#get' do
    it 'processes input' do
      expect(apt_key_cmd).to receive(:run)
        .with(context,
              'adv', '--list-keys', '--with-colons', '--fingerprint', '--fixed-list-mode',
              stdout_destination: :store, stderr_loglevel: :debug)
        .and_return(OpenStruct.new(stdout: key_list))

      expect(provider.get(context)).to eq [
        { ensure: 'present',
          name: '6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9',
          id: '6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9',
          fingerprint: '6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9',
          long: 'EDA0D2388AE22BA9',
          short: '8AE22BA9',
          size: 4096,
          type: :rsa,
          created: '2017-05-22 18:41:53 UTC',
          expiry: '2025-05-20 18:41:53 UTC',
          expired: false },
        { ensure: 'present',
          name: '126C0D24BD8A2942CC7DF8AC7638D0442B90D010',
          id: '126C0D24BD8A2942CC7DF8AC7638D0442B90D010',
          fingerprint: '126C0D24BD8A2942CC7DF8AC7638D0442B90D010',
          long: '7638D0442B90D010',
          short: '2B90D010',
          size: 4096,
          type: :rsa,
          created: '2014-11-21 21:01:13 UTC',
          expiry: '2022-11-19 21:01:13 UTC',
          expired: false },
      ]
    end
  end

  describe '#set(context, changes)' do
    let(:fingerprint) { 'A' * 40 }
    let(:short) { 'A' * 8 }

    context 'when passing in empty changes' do
      it 'does nothing' do
        expect { provider.set(context, {}) }.not_to raise_error
      end
    end

    context 'when managing a up-to-date key' do
      it 'does nothing' do
        expect {
          provider.set(context, fingerprint => {
                         is: {
                           name: fingerprint, ensure: :present
                         },
                         should: {
                           name: fingerprint, ensure: :present
                         },
                       })
        }.not_to raise_error
      end

      context 'without passing in `is:`' do
        it 'does nothing' do
          allow(provider).to receive(:get) # rubocop:disable RSpec/SubjectStub
            .with(context)
            .and_return([
                          {
                            name: fingerprint,
                            ensure: 'present',
                          },
                        ])
          expect {
            provider.set(context, fingerprint => {
                           should: {
                             name: fingerprint, ensure: :present
                           },
                         })
          }.not_to raise_error
        end
      end
    end

    context 'when managing an absent key' do
      it 'does nothing' do
        provider.set(context, fingerprint =>
        {
          is: nil,
          should: {
            name: fingerprint,
            ensure: :absent,
          },
        })
      end
    end

    context 'when fetching a key from the keyserver' do
      it 'updates the system' do
        expect(context).to receive(:creating).with(fingerprint).and_yield
        expect(apt_key_cmd).to receive(:run)
          .with(context,
                'adv', '--keyserver', 'keyserver.example.com', '--recv-keys', fingerprint,
                stdout_loglevel: :notice).and_return(OpenStruct.new(exit_code: 0))
        provider.set(context, fingerprint =>
        {
          is: nil,
          should: {
            name: fingerprint,
            ensure: :present,
            server: :'keyserver.example.com',
          },
        })
      end
    end

    context 'when adding a key from a string' do
      let(:key_tempfile) { instance_double('Tempfile') }

      it 'updates the system' do
        expect(context).to receive(:creating).with(fingerprint).and_yield
        expect(Tempfile).to receive(:new).with('apt_key').and_return(key_tempfile)
        expect(key_tempfile).to receive(:write).with('public gpg key block')
        allow(key_tempfile).to receive(:path).with(no_args).and_return('tempfilename')
        allow(key_tempfile).to receive(:close)
        expect(key_tempfile).to receive(:unlink)
        expect(File).to receive(:executable?).with('/usr/bin/gpg').and_return(true)
        expect(gpg_cmd).to receive(:run)
          .with(context, '--with-fingerprint', '--with-colons', 'tempfilename',
                stdout_destination: :store)
          .and_return(OpenStruct.new(stdout: "\nfpr:::::::::#{fingerprint}:\n"))
        expect(context).to receive(:debug).with('Fingerprint verified against extracted key')

        expect(apt_key_cmd).to receive(:run).with(context, 'add', 'tempfilename').and_return(OpenStruct.new(exit_code: 0))
        provider.set(context, fingerprint =>
        {
          is: nil,
          should: {
            name: fingerprint,
            ensure: :present,
            content: 'public gpg key block',
          },
        })
      end
    end

    describe 'source =>' do
      before(:each) do
        allow(context).to receive(:creating).with(fingerprint).and_yield
        # shortcut excessive stubbing. The add_key_from_content method is already exercised in 'when adding a key from a string'
        allow(provider).to receive(:add_key_from_content).with(context, fingerprint, 'public gpg key block') # rubocop:disable RSpec/SubjectStub
      end

      describe 'a path' do
        it 'updates the system using that file' do
          expect(File).to receive(:exist?).with('/tmp/keyfile').and_return(true)
          expect(File).to receive(:read).with('/tmp/keyfile').and_return('public gpg key block')

          provider.set(context, fingerprint =>
          {
            is: nil,
            should: {
              name: fingerprint,
              ensure: :present,
              source: '/tmp/keyfile',
            },
          })
        end
      end

      describe 'a remote URL' do
        let(:uri) { object_double(URI.parse('http://example.org/gpg.txt')) }

        it 'updates the system using that download' do
          expect(URI).to receive(:parse).with('http://example.org/gpg.txt').and_return(uri)
          expect(uri).to receive(:scheme).and_return('http')
          expect(uri).to receive(:userinfo).and_return(nil)
          expect(uri).to receive(:read).and_return('public gpg key block')

          provider.set(context, fingerprint =>
          {
            is: nil,
            should: {
              name: fingerprint,
              ensure: :present,
              source: 'http://example.org/gpg.txt',
            },
          })
        end
      end

      describe 'a remote URL with username and password' do
        let(:uri) { object_double(URI.parse('http://foo:bar@example.org/gpg.txt')) }
        let(:io) { instance_double('IO') }

        it 'updates the system using that download' do
          expect(URI).to receive(:parse).with('http://foo:bar@example.org/gpg.txt').and_return(uri)
          expect(uri).to receive(:scheme).and_return('http')
          expect(uri).to receive(:userinfo).and_return('foo:bar').twice
          expect(uri).to receive(:userinfo=).with('')
          expect(provider).to receive(:open).with(uri, http_basic_authentication: %w[foo bar]).and_return(io) # rubocop:disable RSpec/SubjectStub
          expect(io).to receive(:read).and_return('public gpg key block')

          provider.set(context, fingerprint =>
          {
            is: nil,
            should: {
              name: fingerprint,
              ensure: :present,
              source: 'http://foo:bar@example.org/gpg.txt',
            },
          })
        end
      end
    end

    context 'when deleting a key' do
      it 'updates the system' do
        expect(context).to receive(:deleting).with(fingerprint).and_yield
        # key_list_lines is exercised in `#get`
        expect(provider).to receive(:key_list_lines).with(no_args).and_return(['a', 'b', fingerprint], ['a', 'b', fingerprint], []) # rubocop:disable RSpec/SubjectStub
        expect(apt_key_cmd).to receive(:run).with(context, 'del', short).and_return(OpenStruct.new(exit_code: 0)).thrice
        provider.set(context, fingerprint =>
        {
          is: {
            name: fingerprint,
            ensure: :present,
            server: :'keyserver.ubuntu.com',
          },
          should: {
            name: fingerprint,
            ensure: :absent,
          },
        })
      end
    end

    context 'when specifying both source and content' do
      it 'reports an error' do
        expect(context).to receive(:failed).with(fingerprint, message: 'The properties `content` and `source` are both set, but mutually exclusive')
        expect {
          provider.set(context, fingerprint => {
                         is: {
                           name: fingerprint, ensure: :present
                         },
                         should: {
                           name: fingerprint, ensure: :present, source: '/tmp/file', content: 'some gpg key'
                         },
                       })
        }.not_to raise_error
      end
    end
  end
end
