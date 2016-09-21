module Xmldsig
  class Canonicalizer
    class UnsupportedException < Xmldsig::Error
    end
    attr_accessor :node, :method, :inclusive_namespaces, :with_comments

    def initialize(node, method = nil, inclusive_namespaces = nil, with_comments = false)
      @node                 = node
      @method               = method
      @inclusive_namespaces = inclusive_namespaces
      @with_comments        = with_comments
    end

    def canonicalize
      node.canonicalize(mode(method), inclusive_namespaces, with_comments)
    end

    private

    def mode(method)
      case method
      when "http://www.w3.org/2001/10/xml-exc-c14n#",
           "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
        Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
      when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        Nokogiri::XML::XML_C14N_1_0
      when "http://www.w3.org/2006/12/xml-c14n11"
        Nokogiri::XML::XML_C14N_1_1
      else
        Nokogiri::XML::XML_C14N_1_0
      end
    end
  end
end
