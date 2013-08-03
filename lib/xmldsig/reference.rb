module Xmldsig
  class Reference
    attr_accessor :reference, :errors

    class ReferencedNodeNotFound < Exception;
    end

    def initialize(reference)
      @reference = reference
      @errors    = []
    end

    def document
      reference.document
    end

    def sign
      self.digest_value = calculate_digest_value
    end

    def referenced_node
      if reference_uri && reference_uri != ""
        id = reference_uri[1..-1]
        if ref = document.dup.at_xpath("//*[@ID='#{id}' or @wsu:Id='#{id}']", NAMESPACES)
          ref
        else
          raise(
              ReferencedNodeNotFound,
              "Could not find the referenced node #{id}'"
          )
        end
      else
        document.dup.root
      end
    end

    def reference_uri
      reference.get_attribute("URI")
    end

    def digest_value
      Base64.decode64 reference.at_xpath("descendant::ds:DigestValue", NAMESPACES).content
    end

    def calculate_digest_value
      transformed = transforms.apply(referenced_node)
      case transformed
        when String
          digest_method.digest transformed
        when Nokogiri::XML::Node
          digest_method.digest Canonicalizer.new(transformed).canonicalize
      end
    end

    def digest_method
      algorithm = reference.at_xpath("descendant::ds:DigestMethod", NAMESPACES).get_attribute("Algorithm")
      case algorithm
        when "http://www.w3.org/2001/04/xmlenc#sha256"
          Digest::SHA2
        when "http://www.w3.org/2000/09/xmldsig#sha1"
          Digest::SHA1
      end
    end

    def digest_value=(digest_value)
      reference.at_xpath("descendant::ds:DigestValue", NAMESPACES).content =
          Base64.encode64(digest_value).chomp
    end

    def transforms
      Transforms.new(reference.xpath("descendant::ds:Transform", NAMESPACES))
    end

    def validate_digest_value
      unless digest_value == calculate_digest_value
        @errors << :digest_value
      end
    end
  end
end
