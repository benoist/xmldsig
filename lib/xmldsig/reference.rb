module Xmldsig
  class Reference
    attr_accessor :reference, :errors, :id_attr

    class ReferencedNodeNotFound < Xmldsig::Error
    end

    def initialize(reference, id_attr = nil, referenced_documents = {})
      @reference = reference
      @errors    = []
      @id_attr = id_attr
      @referenced_documents = referenced_documents
    end

    def document
      reference.document
    end

    def sign
      self.digest_value = calculate_digest_value
    end

    def referenced_node
      if reference_uri && reference_uri != ""
        if @id_attr.nil? && reference_uri.start_with?("cid:")
          content_id = reference_uri[4..-1]
          get_node_by_referenced_documents!(@referenced_documents, content_id)
        elsif !File.extname(reference_uri).gsub('.', '').empty?
          get_node_by_referenced_documents!(@referenced_documents, reference_uri)
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

    private

    def get_node_by_referenced_documents!(referenced_documents, content_id)
      if referenced_documents.has_key?(content_id)
        referenced_documents[content_id].dup
      else
        raise(
            ReferencedNodeNotFound,
            "Could not find referenced document with ContentId #{content_id}"
        )
      end
    end
  end
end
