module Xmldsig
  class Signature
    attr_accessor :signature

    def initialize(signature)
      @signature = signature
    end

    def references
      @references ||= signature.xpath("descendant::ds:Reference", NAMESPACES).map do |node|
        Reference.new(node)
      end
    end

    def errors
      references.flat_map(&:errors) + @errors
    end

    def sign(private_key = nil, certificate = nil, &block)
      references.each(&:sign)
      self.x509_certificate = certificate if certificate
      self.signature_value = calculate_signature_value(private_key, &block)
    end

    def signed_info
      signature.at_xpath("descendant::ds:SignedInfo", NAMESPACES)
    end

    def signature_value
      Base64.decode64 signature.at_xpath("descendant::ds:SignatureValue", NAMESPACES).content
    end

    def x509_certificate
      signature.at_xpath("descendant::ds:X509Certificate", NAMESPACES).content
    end

    def valid?(certificate = nil, &block)
      @errors = []
      references.each { |r| r.errors = [] }
      validate_digest_values
      validate_signature_value(certificate, &block)
      errors.empty?
    end

    private

    def canonicalization_method
      signed_info.at_xpath("descendant::ds:CanonicalizationMethod", NAMESPACES).get_attribute("Algorithm")
    end

    def canonicalized_signed_info
      Canonicalizer.new(signed_info, canonicalization_method).canonicalize
    end

    def calculate_signature_value(private_key, &block)
      if private_key
        private_key.sign(signature_method.new, canonicalized_signed_info)
      else
        yield(canonicalized_signed_info, signature_algorithm)
      end
    end

    def signature_algorithm
      signed_info.at_xpath("descendant::ds:SignatureMethod", NAMESPACES).get_attribute("Algorithm")
    end

    def signature_method
      algorithm = signature_algorithm && signature_algorithm =~ /sha(.*?)$/i && $1.to_i
      case algorithm
        when 256 then
          OpenSSL::Digest::SHA256
        else
          OpenSSL::Digest::SHA1
      end
    end

    def signature_value=(signature_value)
      signature.at_xpath("descendant::ds:SignatureValue", NAMESPACES).content =
          Base64.encode64(signature_value).chomp
    end

    def x509_certificate=(certificate)
      signature.at_xpath("descendant::ds:X509Certificate", NAMESPACES).content =
          certificate.to_s.gsub("-----BEGIN CERTIFICATE-----\n", '').gsub("\n-----END CERTIFICATE-----\n", '').gsub("\n", '')
    end

    def validate_digest_values
      references.each(&:validate_digest_value)
    end

    def validate_signature_value(certificate)
      signature_valid = if certificate
        certificate.public_key.verify(signature_method.new, signature_value, canonicalized_signed_info)
      else
        yield(signature_value, canonicalized_signed_info, signature_algorithm)
      end

      unless signature_valid
        @errors << :signature
      end
    end
  end
end
