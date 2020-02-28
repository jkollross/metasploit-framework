require 'metasploit/framework/login_scanner/http'

module Metasploit
    module Framework
        module LoginScanner
            class FogWebInterface < HTTP
                DEFAULT_PORT = 80
                PRIVATE_TYPES = [ :password ]
                
                def check_setup
                    res = send_request({'uri' => normalize_uri("#{uri}management/index.php")})
                    if res && res.body.include?('FOG Project')
                        return true
                    else
                        return false
                    end
                end
                
                def attempt_login(credential)
                    result_opts = {
                        credential: credential,
                        status: Metasploit::Model::Login::Status::INCORRECT,
                        proof: nil,
                        host: host,
                        port: port,
                        protocol: 'tcp'
                    }
                    begin
                        result_opts.merge!(try_credential(credential))
                    rescue => exception
                        result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: exception.message)
                    end
                    Result.new(result_opts)
                end

                def try_credential(credential)
                    res = send_request({
                        'method' => 'POST',
                        'uri' => normalize_uri("#{uri}management/index.php",
                        'vars_post' => {
                            'uname' => credential.public,
                            'upass' => credential.private,
                            'ulang' => "English",
                            'login' => ''
                        }
                        'cookie' => get_session_id
                    })
                    unless res
                        return {
                                status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, 
                                proof: "Unable to connect."
                        }
                    end
                    if res.headers['Location'] && res.headers['Location'] == '/broadweb/bwproj.asp'
                        return {
                            status: Metasploit::Model::Login::Status::SUCCESSFUL, 
                            proof: res.body
                        }
                    end
                    return {
                        status: Metasploit::Model::Login::Status::INCORRECT, 
                        proof: res.body
                    }
                end

                def get_session_id
                    @session_id ||= lambda {
                        res = send_request({'uri' => normalize_uri("#{uri}management/index.php")})
                        return '' unless  res
                        @session_id = res.get_cookies.scan(/(PHPSESSID=\w+);*/).flatten[0] || ''
                    }.call
                end
            end
        end
    end
end