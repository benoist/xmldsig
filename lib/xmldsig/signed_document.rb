module Xmldsig
  class SignedDocument
    attr_accessor :document

    def initialize(document, options = {})
      @document = Nokogiri::XML(document, nil, nil, Nokogiri::XML::ParseOptions::STRICT)
    end

    def validate(certificate = nil, &block)
      signatures.any? && signatures.all? { |signature| signature.valid?(certificate, &block) }
    end

    def sign(private_key = nil, instruct = true, &block)
      signatures.each { |signature| signature.sign(private_key, &block) }
      instruct ? @document.to_s : @document.root.to_s
    end

    def signed_nodes
      signatures.flat_map(&:references).map(&:referenced_node)
    end

    def signatures
      document.xpath("//ds:Signature", NAMESPACES).reverse.collect { |node| Signature.new(node) } || []
    end
  end
end
