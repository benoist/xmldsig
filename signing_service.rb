require 'base64'

class SigningService

  class << self
    def create_redirect_params(xml, relay_state = "")
      relay_state = relay_state ? "&RelayState=#{CGI.escape(relay_state)}" : ""

      encoded_xml     = Saml::Encoding.to_http_redirect_binding_param(xml)
      response_params = "SAMLResponse=#{encoded_xml}#{relay_state}&SigAlg=#{CGI.escape('http://www.w3.org/2000/09/xmldsig#rsa-sha1')}"
      signature       = CGI.escape(sign_params(:params => response_params, :private_key => Saml::Config.private_key))

      "#{response_params}&Signature=#{signature}"
    end

    def parse_signature_params(query)
      params = {}
      query.split(/[&;]/).each do |pairs|
        key, value = pairs.split('=',2)
        params[key] = value
      end

      relay_state       = params["RelayState"] ? "&RelayState=#{params['RelayState']}" : ""
      "SAMLRequest=#{params['SAMLRequest']}#{relay_state}&SigAlg=#{params['SigAlg']}"
    end

    def sign_params(options={})
      key = OpenSSL::PKey::RSA.new options[:private_key]
      Base64.encode64(key.sign(OpenSSL::Digest::SHA1.new, options[:params])).gsub("\n", '')
    end

    def verify_params(options={})
      cert = OpenSSL::X509::Certificate.new(options[:cert_pem])
      key  = OpenSSL::PKey::RSA.new cert.public_key
      key.verify(OpenSSL::Digest::SHA1.new, Base64.decode64(options[:signature]), parse_signature_params(options[:query_string]))
    end

    def sign!(xml, options={})
      raise "Missing :id_attr option" if options[:id_attr].nil?
      in_tmp_dir do
        options[:private_key_path] = create_tmp_file(options[:private_key])
        xml_file_path              = create_tmp_file xml
        command                    = sign_command(xml_file_path, options)
        result, exitstatus         = run command
        if exitstatus == 0
          result
        else
          run sign_command(xml_file_path, options.merge(:debug => true))
          raise "unable to sign xml: #{command}\ngot error #{exitstatus}:\n#{result}"
        end
      end
    end

    # You can add --pubkey rsapub.pem or --trusted rootcert.pem to check that signature
    # is actually valid. See http://www.aleksey.com/pipermail/xmlsec/2003/001120.html
    def verify_signature!(xml, options={})
      in_tmp_dir do
        if options[:id_attr].blank?
          raise "Missing :id_attr option"
        end
        if options[:cert_pem].blank?
          raise "Missing :cert_pem option"
        else
          options[:cert_path] = create_tmp_file(options[:cert_pem])
        end
        command            = verify_command(create_tmp_file(xml), options)
        result, exitstatus = run command
        if (exitstatus) != 0
          raise "unable to validate xml signature: #{command}\ngot error #{exitstatus}:\n#{result}"
        end
        result
      end
    end
  end

  def self.logger
    @logger ||= Logger.new('test.log')
  end

  private #------------------------------------------------------------------------------

  class << self
    def in_tmp_dir
      Dir.mktmpdir do |dir|
        Dir.chdir(dir) do
          yield
        end
      end
    end

    def create_tmp_file contents
      file_path = "signing_tmp_#{Time.now.to_f}_#{::SecureRandom.hex}"
      File.open(file_path, 'w+') do |f|
        f.puts contents.to_s.strip
      end
      file_path
    end

    def run command
      result     = `#{command}`
      exitstatus = $?.exitstatus
      if exitstatus != 0
        logger.error "Got exitstatus '#{exitstatus}' when running #{command}:\n#{result}"
      end
      [result, exitstatus]
    end

    def sign_command(xml_file_path, options)
      command = xml_sec_command
      command << " --sign "
      command << " --print-debug " if options[:debug]
      command << " --id-attr:#{options[:id_attr]} " if options[:id_attr]
      command << " --enabled-reference-uris empty,same-doc,local "
      command << " --privkey-pem #{options[:private_key_path]} " if options[:private_key_path]
      command << " #{xml_file_path}"
      command
    end

    def verify_command(xml_file_path, options)
      command = xml_sec_command
      command << " --verify "
      command << " --print-debug " if options[:debug]
      command << " --id-attr:#{options[:id_attr]} " if options[:id_attr]
      command << " --enabled-reference-uris empty,same-doc,local "
      command << " --pubkey-cert-pem #{options[:cert_path]}" if options[:cert_path]
      command << " #{xml_file_path} 2>&1"
    end

    def xml_sec_command
      "xmlsec1"
    end
  end
end
