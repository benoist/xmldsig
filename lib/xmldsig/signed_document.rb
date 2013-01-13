module Xmldsig
  class SignedDocument
    attr_accessor :document

    def initialize(document, options = {})
      @document = Nokogiri::XML::Document.parse(document)
    end

    def validate(certificate)
      signatures.all? { |signature| signature.valid?(certificate) }
    end

    def sign(private_key)
      signatures.each { |signature| signature.sign(private_key) }
      @document.to_s
    end

    def signed_nodes
      signatures.collect do |signature|
        document.dup.at_xpath("//*[@Id='#{signature.reference_uri[1..-1]}']")
      end
    end

    def signatures
      document.xpath("//ds:Signature", NAMESPACES).collect { |node| Signature.new(node) } || []
    end
  end
end
