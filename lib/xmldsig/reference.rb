module Xmldsig
  class Reference
    attr_accessor :reference, :errors, :id_attr

    class ReferencedNodeNotFound < Exception;
    end

    def initialize(reference, id_attr = nil)
      @reference = reference
      @errors    = []
      @id_attr = id_attr
    end

    def document
      reference.document
    end

    def sign
      self.digest_value = calculate_digest_value
    end

    def referenced_node
      if reference_uri && reference_uri != ""
        if reference_uri[0] == "/"
          if ref = document.dup.at_xpath(reference_uri)
            ref
          else
            raise(
                ReferencedNodeNotFound,
                "Could not find the referenced node #{reference_uri}'"
            )
          end
        else
          id = reference_uri[1..-1]
          referenced_node_xpath = @id_attr ? "//*[@#{@id_attr}=$uri]" : "//*[@ID=$uri or @wsu:Id=$uri]"
          variable_bindings = { 'uri' => id }
          if ref = document.dup.at_xpath(referenced_node_xpath, NAMESPACES, variable_bindings)
            ref
          else
            raise(
                ReferencedNodeNotFound,
                "Could not find the referenced node #{id}'"
            )
          end
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
      case algorithm =~ /sha(.*?)$/i && $1.to_i
        when 512
          Digest::SHA512
        when 256
          Digest::SHA256
        when 1
          Digest::SHA1
        else
          Digest::SHA256
      end
    end

    def digest_value=(digest_value)
      reference.at_xpath("descendant::ds:DigestValue", NAMESPACES).content =
          Base64.strict_encode64(digest_value).chomp
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
