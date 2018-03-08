module Xmldsig
  class SignedDocument
    attr_accessor :document, :id_attr, :force, :referenced_documents

    def initialize(document, options = {})
      @document = if document.kind_of?(Nokogiri::XML::Document)
        document
      else
        Nokogiri::XML(document, nil, nil, Nokogiri::XML::ParseOptions::STRICT)
      end
      @id_attr  = options[:id_attr] if options[:id_attr]
      @force    = options[:force]
      @referenced_documents = options.fetch(:referenced_documents, {})
    end

    def validate(certificate = nil, schema = nil, &block)
      signatures.any? && signatures.all? { |signature| signature.valid?(certificate, schema, &block) }
    end

    def sign(private_key = nil, instruct = true, &block)
      signatures.reverse.each do |signature|
        signature.sign(private_key, &block) if signature.unsigned? || force
      end

      if instruct
        @document.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
      else
        @document.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML | Nokogiri::XML::Node::SaveOptions::NO_DECLARATION)
      end
    end

    def signed_nodes
      signatures.flat_map(&:references).map(&:referenced_node)
    end

    def signatures
      document.xpath("//ds:Signature", NAMESPACES).
          sort { |left, right| left.ancestors.size <=> right.ancestors.size }.
          collect { |node| Signature.new(node, @id_attr, referenced_documents) } || []
    end
  end
end
