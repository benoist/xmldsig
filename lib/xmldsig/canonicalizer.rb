module Xmldsig
  class Canonicalizer
    attr_accessor :node, :method, :inclusive_namespaces

    def initialize(node, method, inclusive_namespaces = [])
      @node = node
      @method = method
      @inclusive_namespaces = inclusive_namespaces
    end

    def canonicalize
      node.canonicalize(mode(method), inclusive_namespaces)
    end

    private

    def mode(method)
      case method
        when "http://www.w3.org/2001/10/xml-exc-c14n#"
          Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
        when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
          Nokogiri::XML::XML_C14N_1_0
        when "http://www.w3.org/2006/12/xml-c14n11"
          Nokogiri::XML::XML_C14N_1_1
      end
    end
  end
end
