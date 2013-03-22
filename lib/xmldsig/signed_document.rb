module Xmldsig
  class SignedDocument
    attr_accessor :document

    def initialize(document, options = {})
      @document = Nokogiri::XML::Document.parse(document)
    end

    def validate(certificate = nil, &block)
      signatures.empty? ? false : signatures.all? { |signature| signature.valid?(certificate, &block) }
    end

    def sign(private_key = nil, &block)
      signatures.each { |signature| signature.sign(private_key, &block) }
      @document.to_s
    end

    def signed_nodes
      signatures.collect(&:referenced_node)
    end

    def signatures
      document.xpath("//ds:Signature", NAMESPACES).collect { |node| Signature.new(node) } || []
    end
  end
end
