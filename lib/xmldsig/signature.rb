module Xmldsig
  class Signature
    attr_accessor :signature, :errors

    def initialize(signature)
      @signature = signature
      @errors    = []
    end

    def digest_value
      Base64.decode64 signed_info.at_xpath("descendant::ds:DigestValue", NAMESPACES).content
    end

    def document
      signature.document
    end

    def referenced_node
      if reference_uri && reference_uri != ""
        document.dup.at_xpath("//*[@ID='#{reference_uri[1..-1]}']")
      else
        document.dup.at_xpath(signature.parent.path)
      end
    end

    def reference_uri
      signature.at_xpath("descendant::ds:Reference", NAMESPACES).get_attribute("URI")
    end

    def sign(private_key = nil)
      signed_info.at_xpath("descendant::ds:DigestValue").content  =
          Base64.encode64(calculate_digest_value).chomp

      signature_value = if private_key
        calculate_signature_value(private_key)
      elsif block_given?
        yield(canonicalized_signed_info)
      end

      signature.at_xpath("descendant::ds:SignatureValue").content =
          Base64.encode64(signature_value).chomp
    end

    def signed_info
      signature.at_xpath("descendant::ds:SignedInfo", NAMESPACES)
    end

    def signature_value
      Base64.decode64 signature.at_xpath("descendant::ds:SignatureValue", NAMESPACES).content
    end

    def valid?(certificate = nil, &block)
      @errors = []
      validate_digest_value
      validate_signature_value(certificate, &block)
      @errors.empty?
    end

    private

    def calculate_digest_value
      node = transforms.apply(referenced_node)
      digest_method.digest node
    end

    def canonicalization_method
      signed_info.at_xpath("descendant::ds:CanonicalizationMethod", NAMESPACES).get_attribute("Algorithm")
    end

    def canonicalized_signed_info
      Canonicalizer.new(signed_info, canonicalization_method).canonicalize
    end

    def calculate_signature_value(private_key)
      private_key.sign(signature_method.new, canonicalized_signed_info)
    end

    def digest_method
      algorithm = signed_info.at_xpath("descendant::ds:DigestMethod", NAMESPACES).get_attribute("Algorithm")
      case algorithm
        when "http://www.w3.org/2001/04/xmlenc#sha256"
          Digest::SHA2
        when "http://www.w3.org/2000/09/xmldsig#sha1"
          Digest::SHA1
      end
    end

    def signature_method
      algorithm = signed_info.at_xpath("descendant::ds:SignatureMethod", NAMESPACES).get_attribute("Algorithm")
      algorithm = algorithm && algorithm =~ /sha(.*?)$/i && $1.to_i
      case algorithm
        when 256 then
          OpenSSL::Digest::SHA256
        else
          OpenSSL::Digest::SHA1
      end
    end

    def transforms
      Transforms.new(signature.xpath("descendant::ds:Transform", NAMESPACES))
    end

    def validate_digest_value
      unless digest_value == calculate_digest_value
        errors << :digest_value
      end
    end

    def validate_signature_value(certificate)
      signature_valid = if certificate
        certificate.public_key.verify(signature_method.new, signature_value, canonicalized_signed_info)
      else
        yield(signature_value, canonicalized_signed_info)
      end

      unless signature_valid
        errors << :signature
      end
    end
  end
end
