module Xmldsig
  class Signature
    attr_accessor :signature, :errors

    def initialize(signature)
      @signature = signature
      @errors = []
    end

    def digest_value
      Base64.decode64 signed_info.at_xpath("descendant::ds:DigestValue", NAMESPACES).content
    end

    def document
      signature.document
    end

    def referenced_node
      document.dup.at_xpath("//*[@ID='#{reference_uri[1..-1]}']")
    end

    def reference_uri
      signature.at_xpath("descendant::ds:Reference", NAMESPACES).get_attribute("URI")
    end

    def sign(private_key)
      signed_info.at_xpath("descendant::ds:DigestValue").content =
          Base64.encode64(calculate_digest_value).chomp
      signature.at_xpath("descendant::ds:SignatureValue").content =
          Base64.encode64(calculate_signature_value(private_key)).chomp
    end

    def signed_info
      signature.at_xpath("descendant::ds:SignedInfo", NAMESPACES)
    end

    def signature_value
      Base64.decode64 signature.at_xpath("descendant::ds:SignatureValue", NAMESPACES).content
    end

    def valid?(certificate)
      @errors = []
      validate_digest_value
      validate_signature_value(certificate)
      @errors.empty?
    end

    private

    def calculate_digest_value
      node = transforms.apply(referenced_node)
      Digest::SHA2.digest node
    end

    def canonicalization_method
      signed_info.at_xpath("descendant::ds:CanonicalizationMethod", NAMESPACES).get_attribute("Algorithm")
    end

    def canonicalized_signed_info
      Canonicalizer.new(signed_info, canonicalization_method).canonicalize
    end

    def calculate_signature_value(private_key)
      private_key.sign(OpenSSL::Digest::SHA256.new, canonicalized_signed_info)
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
      unless certificate.public_key.verify(OpenSSL::Digest::SHA256.new,
                                           signature_value,
                                           canonicalized_signed_info)
        errors << :signature
      end
    end
  end
end
